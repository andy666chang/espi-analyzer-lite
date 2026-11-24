# Minimal stub of `saleae.analyzers` (HighLevelAnalyzer API) for offline regression tests.


class HighLevelAnalyzer:
    pass


class AnalyzerFrame:
    def __init__(self, type, start_time, end_time, data=None):
        self.type = type
        self.start_time = start_time
        self.end_time = end_time
        self.data = data or {}


class ChoicesSetting:
    def __init__(self, choices, label=''):
        self.choices = choices
        self.label = label


class StringSetting:
    def __init__(self, label=''):
        self.label = label


class NumberSetting:
    def __init__(self, label='', min_value=None, max_value=None):
        self.label = label
