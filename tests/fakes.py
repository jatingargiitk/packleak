"""Fake credentials, assembled at runtime so no token-shaped string sits in the repo."""


def j(*parts):
    return "".join(parts)


STRIPE = j("sk_", "live_", "4eC39HqLyjWDarjtT1zdp7dcZq")
GITHUB = j("gh", "p_", "A" * 20, "b" * 16)
AWS = j("AK", "IA", "Z7Q4N2K8P1R6T3W9")
AWS_DOC = j("AK", "IA", "IOSFODNN7", "EXAMPLE")
OPENAI = j("sk-", "proj-", "x" * 48)
GOOGLE = j("AI", "za", "S" * 35)
PEM = j("-----BEGIN ", "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END ", "RSA PRIVATE KEY-----\n")
