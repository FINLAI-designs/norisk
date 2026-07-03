"""core.tech_stack — Cross-Tool-Zugriff auf den erfassten eigenen Tech-Stack.

Enthält nur den Lazy-Resolver (:mod:`core.tech_stack.resolver`), über den andere
Tools die im ``security_scoring`` erfassten eigenen Software-/Dienst-Namen lesen,
ohne ``security_scoring`` direkt zu importieren.
"""
