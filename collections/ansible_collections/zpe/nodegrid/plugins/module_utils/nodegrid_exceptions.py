#!/usr/bin/python3
# -*- coding: utf-8 -*-

############################################################################
# Nodegrid Exception
class NodegridError(Exception):
    """Base exception for all Nodegrid CLI application-specific errors."""
    pass

# CLICommunicationError
class CLICommunicationError(NodegridError):
    """Nodegrid CLI custom exception for CLI-specific errors."""
    def __init__(self, message, buffer=None, original_exception=None):
        self.message = message
        # It is assumed that the buffer is already decoded.
        self.buffer = buffer 
        self.original_exception = original_exception
        super().__init__(self.message)
    
    def get_tail_buffer(self, lenght=-200):
        if self.buffer:
            return ", ".join([line.strip().replace("\x07", "") for line in  self.buffer[lenght:].splitlines() if len(line.strip())>0])
        else:
            return ""

    def __str__(self):
        # Logs format: Messagge + the last 200 chars of buffer
        buf_tail = f"CLI buffer tail: {self.get_tail_buffer()}" if self.buffer else ""
        return f"{self.message} (Orig: {type(self.original_exception).__name__}) {buf_tail}" if self.original_exception else f"{self.message} {buf_tail}"

class CLIOutputError(NodegridError):
    """Nodegrid CLI custom exception for CLI output errors."""
    def __init__(self, cmd, message, buffer=None, original_exception=None):
        self.cmd = cmd
        self.message = message
        # It is assumed that the buffer is already decoded.
        self.buffer = buffer 
        self.original_exception = original_exception
        super().__init__(self.message)

    def get_tail_buffer(self, lenght=-200):
        if self.buffer:
            return ", ".join([line.strip().replace("\x07", "") for line in  self.buffer[lenght:].splitlines() if len(line.strip())>0])
        else:
            return ""

    def __str__(self):
        # Logs format: Messagge + the last 200 chars of buffer
        buf_tail = f"CLI buffer tail: {self.get_tail_buffer()}" if self.buffer else ""
        return f"CLI cmd: {self.cmd}. {self.message} (Orig: {type(self.original_exception).__name__}) {buf_tail}" if self.original_exception else f"CLI cmd: {self.cmd}. {self.message} {buf_tail}"

# CLISystemRevertError
class CLISystemRevertError(NodegridError):
    """Nodegrid CLI custom exception for 'Error: The system configuration has been changed. Please revert.'."""
    def __init__(self, message, buffer=None, original_exception=None):
        self.message = message
        # It is assumed that the buffer is already decoded.
        self.buffer = buffer 
        self.original_exception = original_exception
        super().__init__(self.message)
    
    def get_tail_buffer(self, lenght=-200):
        if self.buffer:
            return ", ".join([line.strip().replace("\x07", "") for line in  self.buffer[lenght:].splitlines() if len(line.strip())>0])
        else:
            return ""

    def __str__(self):
        # Logs format: Messagge + the last 200 chars of buffer
        buf_tail = f"CLI buffer tail: {self.get_tail_buffer()}" if self.buffer else ""
        return f"{self.message} (Orig: {type(self.original_exception).__name__}) {buf_tail}" if self.original_exception else f"{self.message} {buf_tail}"

# CLITransactionUnderwayError
class CLITransactionUnderwayError(NodegridError):
    """Nodegrid CLI custom exception for 'Error: Another configuration transaction is underway'."""
    def __init__(self, message, buffer=None, original_exception=None):
        self.message = message
        # It is assumed that the buffer is already decoded.
        self.buffer = buffer 
        self.original_exception = original_exception
        super().__init__(self.message)
    
    def get_tail_buffer(self, lenght=-200):
        if self.buffer:
            return ", ".join([line.strip().replace("\x07", "") for line in  self.buffer[lenght:].splitlines() if len(line.strip())>0])
        else:
            return ""

    def __str__(self):
        # Logs format: Messagge + the last 200 chars of buffer
        buf_tail = f"CLI buffer tail: {self.get_tail_buffer()}" if self.buffer else ""
        return f"{self.message} (Orig: {type(self.original_exception).__name__}) {buf_tail}" if self.original_exception else f"{self.message} {buf_tail}"

# CLIAnotherTransactionStartedError
class CLIAnotherTransactionStartedError(NodegridError):
    """Nodegrid CLI custom exception for 'Error: Another session has started a configuration transaction'."""
    def __init__(self, message, buffer=None, original_exception=None):
        self.message = message
        # It is assumed that the buffer is already decoded.
        self.buffer = buffer 
        self.original_exception = original_exception
        super().__init__(self.message)
    
    def get_tail_buffer(self, lenght=-200):
        if self.buffer:
            return ", ".join([line.strip().replace("\x07", "") for line in  self.buffer[lenght:].splitlines() if len(line.strip())>0])
        else:
            return ""

    def __str__(self):
        # Logs format: Messagge + the last 200 chars of buffer
        buf_tail = f"CLI buffer tail: {self.get_tail_buffer()}" if self.buffer else ""
        return f"{self.message} (Orig: {type(self.original_exception).__name__}) {buf_tail}" if self.original_exception else f"{self.message} {buf_tail}"

# CLILicenseError
class CLILicenseError(NodegridError):
    """Nodegrid License custom exception for 'Error: No license available.'"""
    def __init__(self, buffer=None, original_exception=None):
        # It is assumed that the buffer is already decoded.
        self.buffer = buffer 
        self.original_exception = original_exception
        super().__init__('Error: No license available')
    
    def get_tail_buffer(self, lenght=-200):
        if self.buffer:
            return ", ".join([line.strip().replace("\x07", "") for line in  self.buffer[lenght:].splitlines() if len(line.strip())>0])
        else:
            return ""

    def __str__(self):
        # Logs format: Messagge + the last 200 chars of buffer
        buf_tail = f"CLI buffer tail: {self.get_tail_buffer()}" if self.buffer else ""
        return f"Error: No license available. (Orig: {type(self.original_exception).__name__}) {buf_tail}" if self.original_exception else f"Error: No license available. {buf_tail}"

class InputValidationError(NodegridError):
    """Nodegrid Input Validation exception."""
    def __init__(self, message, original_exception=None):
        self.message = message
        self.original_exception = original_exception
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message} (Orig: {type(self.original_exception).__name__})" if self.original_exception else f"{self.message}"
#     
############################################################################
