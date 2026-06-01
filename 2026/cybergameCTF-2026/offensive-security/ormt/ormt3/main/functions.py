from django.db.models import Aggregate

class Convert(Aggregate):
    function = "SUM"
    template = "%(function)s(%(expressions)s) * %(rate)s"
    allow_distinct = False
    arity = 1
    default_rate = '0.86'

    def __init__(self, expression, rate=None, **extra):
        extra.setdefault("rate", self.default_rate if rate is None else rate)
        super().__init__(expression, **extra)