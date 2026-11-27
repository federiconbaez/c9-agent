class AgentError(Exception):
    """Base de errores del agente. El mensaje nunca incluye contenido del trabajo."""


class SignatureError(AgentError):
    pass


class ReplayError(AgentError):
    pass


class JobFormatError(AgentError):
    pass


class ActionNotAllowed(AgentError):
    pass


class ArgumentError(AgentError):
    pass
