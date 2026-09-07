//! The `--provider` choice surface: which login providers map to which
//! `ProviderChoice`, and how the choice round-trips to CLI arg values.
//! Extracted from `provider_init` so the mapping data sits beside its
//! accessors instead of bloating the init flow file.

use crate::provider_catalog::{
    LoginProviderDescriptor, LoginProviderTarget, OpenAiCompatibleProfile,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ProviderChoice {
    Jcode,
    Claude,
    #[value(alias = "claude-api", alias = "anthropic-key", alias = "claude-key")]
    AnthropicApi,
    #[deprecated(
        note = "Claude Code CLI subprocess transport is deprecated; use ProviderChoice::Claude for native Anthropic OAuth/API transport"
    )]
    #[value(alias = "claude-subprocess", hide = true)]
    ClaudeSubprocess,
    Openai,
    #[value(
        alias = "openai-key",
        alias = "openai-apikey",
        alias = "openai-platform"
    )]
    OpenaiApi,
    Openrouter,
    #[value(alias = "aws-bedrock", alias = "aws_bedrock")]
    Bedrock,
    #[value(alias = "azure-openai", alias = "aoai")]
    Azure,
    #[value(alias = "opencode-zen", alias = "zen")]
    Opencode,
    #[value(alias = "opencodego")]
    OpencodeGo,
    #[value(alias = "z.ai", alias = "z-ai", alias = "zai-coding")]
    Zai,
    #[value(
        alias = "kimi-code",
        alias = "kimi-coding",
        alias = "kimi-coding-plan",
        alias = "kimi-for-coding",
        alias = "moonshot-coding"
    )]
    Kimi,
    #[value(alias = "302.ai")]
    Ai302,
    Baseten,
    #[value(alias = "conifer-api")]
    Conifer,
    Cortecs,
    #[value(alias = "cgc", alias = "comtegra-gpu-cloud")]
    Comtegra,
    Deepseek,
    #[value(alias = "fpt-ai", alias = "fptcloud", alias = "fpt-cloud")]
    Fpt,
    Firmware,
    #[value(alias = "hugging-face", alias = "hf")]
    HuggingFace,
    #[value(alias = "moonshot")]
    MoonshotAi,
    Nebius,
    Scaleway,
    Stackit,
    Groq,
    #[value(alias = "mistralai")]
    Mistral,
    #[value(alias = "pplx")]
    Perplexity,
    #[value(alias = "together", alias = "together-ai")]
    TogetherAi,
    #[value(alias = "deep-infra")]
    Deepinfra,
    #[value(alias = "fireworks-ai", alias = "fireworks.ai")]
    Fireworks,
    #[value(alias = "novita-ai", alias = "novita.ai")]
    Novita,
    #[value(alias = "orca-router")]
    Orcarouter,
    #[value(alias = "minimax-ai", alias = "minimaxi")]
    Minimax,
    #[value(alias = "x.ai", alias = "x-ai", alias = "grok")]
    Xai,
    /// Grok Build subscription via the authenticated Grok CLI ACP transport.
    #[value(name = "grok-build")]
    GrokBuild,
    #[value(alias = "nvidia", alias = "nim")]
    NvidiaNim,
    #[value(alias = "xiaomi", alias = "mimo", alias = "xiaomi-mimo-api")]
    XiaomiMimo,
    #[value(
        alias = "meta",
        alias = "muse",
        alias = "muse-spark",
        alias = "meta-model-api",
        alias = "meta-ai"
    )]
    MetaMuse,
    #[value(alias = "celeris-ai", alias = "celeris1", alias = "celeris-1")]
    Celeris,
    #[value(alias = "lm-studio")]
    Lmstudio,
    Ollama,
    Chutes,
    #[value(alias = "cerebrascode", alias = "cerberascode")]
    Cerebras,
    #[value(alias = "belvedir.ai", alias = "belvedir-ai")]
    Belvedir,
    #[value(
        alias = "bailian",
        alias = "aliyun-bailian",
        alias = "coding-plan",
        alias = "alibaba-coding"
    )]
    AlibabaCodingPlan,
    #[value(alias = "compat", alias = "custom")]
    OpenaiCompatible,
    Cursor,
    Copilot,
    Gemini,
    #[value(
        alias = "gemini-key",
        alias = "gemini-apikey",
        alias = "google-ai-studio",
        alias = "ai-studio"
    )]
    GeminiApi,
    Antigravity,
    Google,
    Auto,
}

impl ProviderChoice {
    #[allow(deprecated)]
    pub fn as_arg_value(&self) -> &'static str {
        match self {
            Self::Jcode => "jcode",
            Self::Claude => "claude",
            Self::AnthropicApi => "anthropic-api",
            Self::ClaudeSubprocess => "claude-subprocess",
            Self::Openai => "openai",
            Self::OpenaiApi => "openai-api",
            Self::Openrouter => "openrouter",
            Self::Bedrock => "bedrock",
            Self::Azure => "azure",
            Self::Opencode => "opencode",
            Self::OpencodeGo => "opencode-go",
            Self::Zai => "zai",
            Self::Kimi => "kimi",
            Self::Ai302 => "302ai",
            Self::Baseten => "baseten",
            Self::Conifer => "conifer",
            Self::Cortecs => "cortecs",
            Self::Comtegra => "comtegra",
            Self::Deepseek => "deepseek",
            Self::Fpt => "fpt",
            Self::Firmware => "firmware",
            Self::HuggingFace => "huggingface",
            Self::MoonshotAi => "moonshotai",
            Self::Nebius => "nebius",
            Self::Scaleway => "scaleway",
            Self::Stackit => "stackit",
            Self::Groq => "groq",
            Self::Mistral => "mistral",
            Self::Perplexity => "perplexity",
            Self::TogetherAi => "togetherai",
            Self::Deepinfra => "deepinfra",
            Self::Fireworks => "fireworks",
            Self::Novita => "novita",
            Self::Orcarouter => "orcarouter",
            Self::Minimax => "minimax",
            Self::Xai => "xai",
            Self::GrokBuild => "grok-build",
            Self::NvidiaNim => "nvidia-nim",
            Self::XiaomiMimo => "xiaomi-mimo",
            Self::MetaMuse => "meta-muse",
            Self::Celeris => "celeris",
            Self::Lmstudio => "lmstudio",
            Self::Ollama => "ollama",
            Self::Chutes => "chutes",
            Self::Cerebras => "cerebras",
            Self::Belvedir => "belvedir",
            Self::AlibabaCodingPlan => "alibaba-coding-plan",
            Self::OpenaiCompatible => "openai-compatible",
            Self::Cursor => "cursor",
            Self::Copilot => "copilot",
            Self::Gemini => "gemini",
            Self::GeminiApi => "gemini-api",
            Self::Antigravity => "antigravity",
            Self::Google => "google",
            Self::Auto => "auto",
        }
    }
}

#[allow(deprecated)]
const PROVIDER_CHOICE_LOGIN_PROVIDERS: &[(ProviderChoice, LoginProviderDescriptor)] = &[
    (
        ProviderChoice::Jcode,
        crate::provider_catalog::JCODE_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Claude,
        crate::provider_catalog::CLAUDE_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::AnthropicApi,
        crate::provider_catalog::ANTHROPIC_API_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::ClaudeSubprocess,
        crate::provider_catalog::CLAUDE_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Openai,
        crate::provider_catalog::OPENAI_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::OpenaiApi,
        crate::provider_catalog::OPENAI_API_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Openrouter,
        crate::provider_catalog::OPENROUTER_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Bedrock,
        crate::provider_catalog::BEDROCK_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Azure,
        crate::provider_catalog::AZURE_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Opencode,
        crate::provider_catalog::OPENCODE_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::OpencodeGo,
        crate::provider_catalog::OPENCODE_GO_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Zai,
        crate::provider_catalog::ZAI_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Kimi,
        crate::provider_catalog::KIMI_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Ai302,
        crate::provider_catalog::AI302_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Baseten,
        crate::provider_catalog::BASETEN_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Conifer,
        crate::provider_catalog::CONIFER_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Cortecs,
        crate::provider_catalog::CORTECS_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Comtegra,
        crate::provider_catalog::COMTEGRA_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Deepseek,
        crate::provider_catalog::DEEPSEEK_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Fpt,
        crate::provider_catalog::FPT_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Firmware,
        crate::provider_catalog::FIRMWARE_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::HuggingFace,
        crate::provider_catalog::HUGGING_FACE_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::MoonshotAi,
        crate::provider_catalog::MOONSHOT_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Nebius,
        crate::provider_catalog::NEBIUS_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Scaleway,
        crate::provider_catalog::SCALEWAY_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Stackit,
        crate::provider_catalog::STACKIT_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Groq,
        crate::provider_catalog::GROQ_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Mistral,
        crate::provider_catalog::MISTRAL_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Perplexity,
        crate::provider_catalog::PERPLEXITY_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::TogetherAi,
        crate::provider_catalog::TOGETHER_AI_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Deepinfra,
        crate::provider_catalog::DEEPINFRA_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Fireworks,
        crate::provider_catalog::FIREWORKS_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Novita,
        crate::provider_catalog::NOVITA_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Orcarouter,
        crate::provider_catalog::ORCAROUTER_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Minimax,
        crate::provider_catalog::MINIMAX_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Xai,
        crate::provider_catalog::XAI_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::GrokBuild,
        crate::provider_catalog::GROK_BUILD_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::NvidiaNim,
        crate::provider_catalog::NVIDIA_NIM_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::XiaomiMimo,
        crate::provider_catalog::XIAOMI_MIMO_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::MetaMuse,
        crate::provider_catalog::META_MUSE_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Celeris,
        crate::provider_catalog::CELERIS_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Lmstudio,
        crate::provider_catalog::LMSTUDIO_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Ollama,
        crate::provider_catalog::OLLAMA_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Chutes,
        crate::provider_catalog::CHUTES_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Cerebras,
        crate::provider_catalog::CEREBRAS_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Belvedir,
        crate::provider_catalog::BELVEDIR_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::AlibabaCodingPlan,
        crate::provider_catalog::ALIBABA_CODING_PLAN_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::OpenaiCompatible,
        crate::provider_catalog::OPENAI_COMPAT_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Cursor,
        crate::provider_catalog::CURSOR_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Copilot,
        crate::provider_catalog::COPILOT_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Gemini,
        crate::provider_catalog::GEMINI_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::GeminiApi,
        crate::provider_catalog::GEMINI_API_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Antigravity,
        crate::provider_catalog::ANTIGRAVITY_LOGIN_PROVIDER,
    ),
    (
        ProviderChoice::Google,
        crate::provider_catalog::GOOGLE_LOGIN_PROVIDER,
    ),
];

pub fn login_provider_choice_mappings() -> &'static [(ProviderChoice, LoginProviderDescriptor)] {
    PROVIDER_CHOICE_LOGIN_PROVIDERS
}

pub fn profile_for_choice(choice: &ProviderChoice) -> Option<OpenAiCompatibleProfile> {
    match login_provider_for_choice(choice)?.target {
        LoginProviderTarget::OpenAiCompatible(profile) => Some(profile),
        _ => None,
    }
}

#[allow(deprecated)]
pub fn login_provider_for_choice(choice: &ProviderChoice) -> Option<LoginProviderDescriptor> {
    PROVIDER_CHOICE_LOGIN_PROVIDERS
        .iter()
        .find(|(candidate, _)| candidate == choice)
        .map(|(_, provider)| *provider)
}

#[allow(deprecated)]
pub fn choice_for_login_provider(provider: LoginProviderDescriptor) -> Option<ProviderChoice> {
    PROVIDER_CHOICE_LOGIN_PROVIDERS
        .iter()
        .find(|(choice, candidate)| {
            candidate.id == provider.id && !matches!(choice, ProviderChoice::ClaudeSubprocess)
        })
        .map(|(choice, _)| *choice)
}
