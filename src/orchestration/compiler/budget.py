class BudgetManager:
    def __init__(self, nano_usd: int):
        self._total = nano_usd
        self._spent = 0

    def allocate(self, amount: int) -> bool:
        if self._spent + amount > self._total:
            return False
        self._spent += amount
        return True

    def remaining(self) -> int:
        return self._total - self._spent
