"""
Validation Checksums for Client-Side Detection (Section 6.2 & Section 9 C4)
Eliminates false positives from random digit strings.
Ported from module2/extension/shared/checksums.js.
"""

class Verhoeff:
    d = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
    ]
    p = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
    ]

    @classmethod
    def validate(cls, text: str) -> bool:
        if not text or not isinstance(text, str):
            return False
        clean = "".join(text.split())
        if not (clean.isdigit() and len(clean) == 12):
            return False
        c = 0
        digits = [int(ch) for ch in reversed(clean)]
        for i, digit in enumerate(digits):
            c = cls.d[c][cls.p[i % 8][digit]]
        return c == 0


class Luhn:
    @classmethod
    def validate(cls, text: str) -> bool:
        if not text or not isinstance(text, str):
            return False
        clean = text.replace(" ", "").replace("-", "")
        if not (clean.isdigit() and 13 <= len(clean) <= 19):
            return False
        total = 0
        alternate = False
        for ch in reversed(clean):
            n = int(ch)
            if alternate:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
            alternate = not alternate
        return total % 10 == 0
