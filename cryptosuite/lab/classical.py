"""EDUCATIONAL IMPLEMENTATIONS — NOT FOR PRODUCTION USE."""

from __future__ import annotations

import math

from cryptosuite.utils.exceptions import ValidationError

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def caesar(text: str, shift: int, *, decrypt: bool = False) -> str:
    """Apply the educational Caesar substitution cipher."""
    offset = -shift if decrypt else shift
    return "".join(_shift_character(char, offset) for char in text)


def vigenere(text: str, key: str, *, decrypt: bool = False) -> str:
    """Apply Vigenere while preserving non-letter characters."""
    shifts = [ord(char) - 65 for char in key.upper() if char in ALPHABET]
    if not shifts:
        raise ValidationError("Vigenere key must contain letters.")
    output = []
    index = 0
    for char in text:
        if char.upper() in ALPHABET:
            shift = shifts[index % len(shifts)] * (-1 if decrypt else 1)
            output.append(_shift_character(char, shift))
            index += 1
        else:
            output.append(char)
    return "".join(output)


def affine(text: str, a: int, b: int, *, decrypt: bool = False) -> str:
    """Apply the educational affine substitution cipher."""
    if math.gcd(a, 26) != 1:
        raise ValidationError("Affine key 'a' must be coprime with 26.")
    inverse = pow(a, -1, 26)
    output = []
    for char in text:
        upper = char.upper()
        if upper not in ALPHABET:
            output.append(char)
            continue
        value = ord(upper) - 65
        transformed = inverse * (value - b) % 26 if decrypt else (a * value + b) % 26
        result = chr(transformed + 65)
        output.append(result if char.isupper() else result.lower())
    return "".join(output)


def rail_fence(text: str, rails: int, *, decrypt: bool = False) -> str:
    """Apply the educational rail-fence transposition cipher."""
    if not isinstance(rails, int) or not 2 <= rails <= 100:
        raise ValidationError("Rail count must be between 2 and 100.")
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    positions = [pattern[index % len(pattern)] for index in range(len(text))]
    if not decrypt:
        return "".join(text[index] for rail in range(rails) for index, value in enumerate(positions) if value == rail)
    counts = [positions.count(rail) for rail in range(rails)]
    buckets = []
    cursor = 0
    for count in counts:
        buckets.append(list(text[cursor : cursor + count]))
        cursor += count
    return "".join(buckets[rail].pop(0) for rail in positions)


def playfair(text: str, key: str, *, decrypt: bool = False) -> str:
    """Apply Playfair using the conventional I/J-combined alphabet."""
    square = _playfair_square(key)
    pairs = _playfair_pairs(text, decrypt)
    output = []
    for first, second in pairs:
        first_index, second_index = square.index(first), square.index(second)
        row_a, col_a = divmod(first_index, 5)
        row_b, col_b = divmod(second_index, 5)
        direction = -1 if decrypt else 1
        if row_a == row_b:
            output.extend((square[row_a * 5 + (col_a + direction) % 5], square[row_b * 5 + (col_b + direction) % 5]))
        elif col_a == col_b:
            output.extend((square[((row_a + direction) % 5) * 5 + col_a], square[((row_b + direction) % 5) * 5 + col_b]))
        else:
            output.extend((square[row_a * 5 + col_b], square[row_b * 5 + col_a]))
    return "".join(output)


def hill_2x2(text: str, matrix: tuple[tuple[int, int], tuple[int, int]], *, decrypt: bool = False) -> str:
    """Apply a two-by-two Hill cipher to normalized A-Z text."""
    normalized = "".join(char for char in text.upper() if char in ALPHABET)
    if len(normalized) % 2:
        normalized += "X"
    a, b = matrix[0]
    c, d = matrix[1]
    determinant = (a * d - b * c) % 26
    if math.gcd(determinant, 26) != 1:
        raise ValidationError("Hill matrix is not invertible modulo 26.")
    if decrypt:
        inverse = pow(determinant, -1, 26)
        a, b, c, d = d * inverse % 26, -b * inverse % 26, -c * inverse % 26, a * inverse % 26
    output = []
    for index in range(0, len(normalized), 2):
        x, y = ord(normalized[index]) - 65, ord(normalized[index + 1]) - 65
        output.extend((chr((a * x + b * y) % 26 + 65), chr((c * x + d * y) % 26 + 65)))
    return "".join(output)


def _shift_character(char: str, shift: int) -> str:
    if char.upper() not in ALPHABET:
        return char
    base = ord("A" if char.isupper() else "a")
    return chr((ord(char) - base + shift) % 26 + base)


def _playfair_square(key: str) -> str:
    cleaned = (key + ALPHABET).upper().replace("J", "I")
    return "".join(dict.fromkeys(char for char in cleaned if char in ALPHABET and char != "J"))


def _playfair_pairs(text: str, decrypt: bool) -> list[tuple[str, str]]:
    cleaned = "".join(char for char in text.upper().replace("J", "I") if char in ALPHABET)
    if decrypt:
        if len(cleaned) % 2:
            raise ValidationError("Playfair ciphertext length must be even.")
        return list(zip(cleaned[::2], cleaned[1::2], strict=True))
    pairs = []
    index = 0
    while index < len(cleaned):
        first = cleaned[index]
        second = cleaned[index + 1] if index + 1 < len(cleaned) else "X"
        if first == second:
            second = "X"
            index += 1
        else:
            index += 2
        pairs.append((first, second))
    return pairs

