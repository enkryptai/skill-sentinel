import os
from typing import Any, List

from crewai import LLM, Agent, Crew, Process, Task
from crewai.agents.agent_builder.base_agent import BaseAgent
from crewai.llm import CONTEXT_WINDOW_USAGE_RATIO
from crewai.llms.base_llm import BaseLLM
from crewai.project import CrewBase, agent, crew, task
from crewai.types.usage_metrics import UsageMetrics
from pydantic import PrivateAttr

# Defined in providers.py (no heavy imports, so the CLI can consult it before
# importing CrewAI); re-exported here for backwards compatibility.
from skill_sentinel.providers import (  # noqa: F401
    LOCAL_PROVIDER_PREFIXES,
    is_local_model,
)
from skill_sentinel.tools.custom_tool import ReadFileTool, GrepTool


# --------------------------------------------------------------------------- #
# Local / self-hosted models
# --------------------------------------------------------------------------- #


def _context_window_override(llm: LLM, size: int) -> None:
    """Force ``llm.get_context_window_size()`` to return ``size``.

    CrewAI derives the context window by prefix-matching a hardcoded table of
    hosted model names. A self-hosted model matches nothing and silently falls
    back to 8192 * 0.85 = 6963 tokens, which is far below what a typical local
    server is configured for -- and below Skill Sentinel's own prompt overhead,
    so the crew would summarise or fail mid-scan on a model that can easily
    hold the whole scan.

    ``LLM`` accepts a ``context_window_size`` constructor argument, but the
    native (non-litellm) provider classes do not define that field and drop it
    without error, so the override has to replace the method instead.
    """
    base = type(llm)
    llm.__class__ = type(
        f"ContextWindowOverride{base.__name__}",
        (base,),
        {"get_context_window_size": lambda self: size},
    )


# --------------------------------------------------------------------------- #
# Provider + model fallback
# --------------------------------------------------------------------------- #
# Error name/message fragments that mean "try the next model": transient or
# provider-level failures (rate limit, quota, timeout, 5xx, connection, auth).
_RETRYABLE_SIGNALS = (
    "ratelimit", "rate limit", "429", "quota", "insufficient_quota", "overloaded",
    "timeout", "timed out", "503", "502", "500", "service unavailable",
    "serviceunavailable", "internalservererror", "apiconnection", "connection",
    "unauthorized", "authentication", "401",
)


def _is_retryable(exc: Exception) -> bool:
    blob = f"{type(exc).__name__} {exc}".lower()
    return any(sig in blob for sig in _RETRYABLE_SIGNALS)


class FallbackLLM(BaseLLM):
    """A crew LLM that tries the primary model, then each fallback model in turn
    when a call fails with a retryable error. Each model may be a different
    provider (e.g. ``openai/gpt-5.4-mini`` -> ``anthropic/...`` -> ``groq/...``).
    """

    _llms: List[LLM] = PrivateAttr(default_factory=list)

    def __init__(self, llms: List[LLM]) -> None:
        if not llms:
            raise ValueError("FallbackLLM requires at least one model")
        primary = llms[0]
        super().__init__(
            model=primary.model, provider=getattr(primary, "provider", "openai")
        )
        self._llms = list(llms)

    def call(
        self,
        messages: Any,
        tools: Any = None,
        callbacks: Any = None,
        available_functions: Any = None,
        from_task: Any = None,
        from_agent: Any = None,
        response_model: Any = None,
    ) -> Any:
        stop = self.stop_sequences
        last_exc: Exception | None = None
        for index, llm in enumerate(self._llms):
            llm.stop = stop  # propagate any active stop sequences to the delegate
            try:
                return llm.call(
                    messages,
                    tools=tools,
                    callbacks=callbacks,
                    available_functions=available_functions,
                    from_task=from_task,
                    from_agent=from_agent,
                    response_model=response_model,
                )
            except Exception as exc:
                last_exc = exc
                if index == len(self._llms) - 1 or not _is_retryable(exc):
                    raise
                print(
                    f"[Skill Sentinel] model '{llm.model}' failed "
                    f"({type(exc).__name__}); falling back to "
                    f"'{self._llms[index + 1].model}'"
                )
        raise last_exc  # pragma: no cover - loop always returns or raises

    def get_token_usage_summary(self) -> UsageMetrics:
        """Aggregate token usage across every delegate. CrewAI reads usage from
        the agent's ``llm`` (this wrapper); without this override only the
        wrapper's own empty counters are seen and totals come back as zero."""
        total = UsageMetrics()
        for llm in self._llms:
            total.add_usage_metrics(llm.get_token_usage_summary())
        return total

    # Capability checks delegate to the primary model.
    def supports_function_calling(self) -> bool:
        return self._llms[0].supports_function_calling()

    def supports_stop_words(self) -> bool:
        return self._llms[0].supports_stop_words()

    def get_context_window_size(self) -> int:
        return self._llms[0].get_context_window_size()


def build_llm() -> BaseLLM:
    """Build the crew LLM from environment variables.

    Primary model: ``OPENAI_MODEL_NAME`` (set by ``scan()`` / the caller) or
    ``PRIMARY_MODEL``, else ``gpt-5.4-mini``. Fallbacks: ``FALLBACK_MODELS``
    (comma-separated, e.g. ``anthropic/claude-...,groq/llama-...``). Each model
    authenticates with its provider's standard key env var (``OPENAI_API_KEY``,
    ``ANTHROPIC_API_KEY``, ...).

    Local / self-hosted servers (vLLM, Ollama) are addressed with a provider
    prefix, e.g. ``PRIMARY_MODEL=hosted_vllm/<served-model-name>``. Two
    optional variables tune them:

    ``LLM_API_BASE``
        Endpoint of the primary model's server, e.g.
        ``http://localhost:8000/v1``. Only needed when the server is not at the
        provider's default (vLLM: ``http://localhost:8000/v1``, Ollama:
        ``http://localhost:11434/v1``), such as a container or remote host.
    ``LLM_CONTEXT_WINDOW``
        Context window of the primary model in tokens -- see
        ``_context_window_override``. Set it to the server's configured
        maximum (vLLM's ``--max-model-len``).

    Returns a plain ``LLM`` when no fallbacks are configured (unchanged
    single-model behaviour), otherwise a ``FallbackLLM``. A fallback that fails
    to construct is skipped with a warning so it can never break the primary.
    """
    primary = (
        os.environ.get("OPENAI_MODEL_NAME")
        or os.environ.get("PRIMARY_MODEL")
        or "gpt-5.4-mini"
    )
    fallbacks = [
        m.strip() for m in os.environ.get("FALLBACK_MODELS", "").split(",") if m.strip()
    ]

    primary_kwargs: dict[str, Any] = {}
    api_base = os.environ.get("LLM_API_BASE", "").strip()
    if api_base:
        # Native providers read ``base_url``; the litellm fallback path reads
        # ``api_base``. Passing only ``api_base`` leaves a native provider on
        # its default endpoint, so set both.
        primary_kwargs["base_url"] = api_base
        primary_kwargs["api_base"] = api_base

    llms: List[LLM] = [LLM(model=primary, **primary_kwargs)]

    context_window = os.environ.get("LLM_CONTEXT_WINDOW", "").strip()
    if context_window:
        try:
            size = int(context_window)
            if size <= 0:
                raise ValueError("must be positive")
        except ValueError as exc:
            print(
                f"[Skill Sentinel] ignoring invalid LLM_CONTEXT_WINDOW "
                f"'{context_window}': {exc}"
            )
        else:
            # CrewAI reserves part of the window for the completion; applying
            # the same ratio it uses for known models keeps that headroom.
            _context_window_override(llms[0], int(size * CONTEXT_WINDOW_USAGE_RATIO))

    for m in fallbacks:
        try:
            llms.append(LLM(model=m))
        except Exception as exc:  # a fallback must never break the primary; a
            # provider whose extra isn't installed is skipped with a warning.
            print(f"[Skill Sentinel] ignoring fallback model '{m}': {exc}")
    return llms[0] if len(llms) == 1 else FallbackLLM(llms)


@CrewBase
class SkillScanner():
    """SkillScanner crew — analyzes Agent Skill packages for security threats."""

    agents: List[BaseAgent]
    tasks: List[Task]

    # ------------------------------------------------------------------
    # Agents
    # ------------------------------------------------------------------

    @agent
    def skillmd_analyzer_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['skillmd_analyzer_agent'],  # type: ignore[index]
            tools=[ReadFileTool()],
            llm=build_llm(),
            max_iter=15,
            verbose=False,
        )

    @agent
    def file_verification_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['file_verification_agent'],  # type: ignore[index]
            tools=[ReadFileTool(), GrepTool()],
            llm=build_llm(),
            max_iter=25,
            verbose=False,
        )

    @agent
    def report_synthesizer_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['report_synthesizer_agent'],  # type: ignore[index]
            tools=[],  # Pure synthesis — no tools needed
            llm=build_llm(),
            verbose=False,
        )

    # ------------------------------------------------------------------
    # Tasks
    # ------------------------------------------------------------------

    @task
    def skillmd_analysis_task(self) -> Task:
        return Task(
            config=self.tasks_config['skillmd_analysis_task'],  # type: ignore[index]
        )

    @task
    def file_verification_task(self) -> Task:
        return Task(
            config=self.tasks_config['file_verification_task'],  # type: ignore[index]
            context=[self.skillmd_analysis_task()],
        )

    @task
    def report_synthesis_task(self) -> Task:
        return Task(
            config=self.tasks_config['report_synthesis_task'],  # type: ignore[index]
            context=[self.skillmd_analysis_task(), self.file_verification_task()],
            output_file='report.json',
        )

    def _make_report_synthesis_task(
        self,
        context_tasks: List[Task],
        output_file: str = "report.json",
    ) -> Task:
        """Create the report synthesis task with dynamic context."""
        return Task(
            config=self.tasks_config['report_synthesis_task'],  # type: ignore[index]
            context=context_tasks,
            output_file=output_file,
        )

    # ------------------------------------------------------------------
    # Crew builders
    # ------------------------------------------------------------------

    @crew
    def crew(self) -> Crew:
        """Default crew with all tasks (used by CrewAI CLI commands)."""
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=False,
        )

    def build_crew(
        self,
        include_file_verification: bool = True,
        output_file: str = "report.json",
    ) -> Crew:
        """
        Build a crew with explicit task control.

        Args:
            include_file_verification: If False, skip the file verification task
                (e.g., when the skill package contains only SKILL.md).
            output_file: Path where the final report JSON will be written.
        """
        agent_list = [
            self.skillmd_analyzer_agent(),
            self.report_synthesizer_agent(),
        ]
        task_list = [self.skillmd_analysis_task()]

        if include_file_verification:
            agent_list.insert(1, self.file_verification_agent())
            fv_task = self.file_verification_task()
            task_list.append(fv_task)

        # Report synthesis always last, with context from all preceding tasks
        report_task = self._make_report_synthesis_task(
            context_tasks=list(task_list),
            output_file=output_file,
        )
        task_list.append(report_task)

        return Crew(
            agents=agent_list,
            tasks=task_list,
            process=Process.sequential,
            verbose=False,
        )
