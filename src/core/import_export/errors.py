class ExchangeError(RuntimeError):
    """Base error for secure data exchange operations."""


class ExportError(ExchangeError):
    """Raised when an export cannot be completed safely."""


class ImportValidationError(ExchangeError):
    """Raised when imported content is invalid or unsafe."""


class SharingError(ExchangeError):
    """Raised when a sharing operation fails validation."""


class QRCodeError(ExchangeError):
    """Raised when a QR payload cannot be generated or validated."""
