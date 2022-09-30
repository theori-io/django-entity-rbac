class InconsistentDatabaseValuesError(Exception):
    """
    Raises when a database query returned unexpected values.
    Shall never happen in normal circumstances.
    """