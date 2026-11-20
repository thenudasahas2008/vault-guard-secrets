import math

def calculate_shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return round(entropy, 2)

def is_high_entropy_secret(token: str, threshold: float = 4.2) -> bool:
    """Returns True if the token has high randomness typical of generated API keys."""
    # Ignore purely numeric or common words
    if token.isdigit() or len(token) < 16:
        return False
    return calculate_shannon_entropy(token) >= threshold
