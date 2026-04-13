"""
Known Devices Database for WhisperPair PoC

Provides manufacturer-specific device metadata and quirk flags used to
adjust exploit behavior (retry logic, MTU negotiation, response format, etc.).
"""

# ==============================================================================
# QUIRK FLAG CONSTANTS
# ==============================================================================

# Device requires seeker address to be included in KBP request
QUIRK_NEEDS_SEEKER_ADDR = "QUIRK_NEEDS_SEEKER_ADDR"

# Device requires bonding flag to be set in KBP request
QUIRK_NEEDS_BONDING_FLAG = "QUIRK_NEEDS_BONDING_FLAG"

# Device has slow GATT response times; increase timeouts
QUIRK_SLOW_GATT = "QUIRK_SLOW_GATT"

# Device requires MTU negotiation to exactly 83 bytes
QUIRK_MTU_83 = "QUIRK_MTU_83"

# Device requires a connection retry after initial failure
QUIRK_RETRY_CONNECT = "QUIRK_RETRY_CONNECT"

# Device does not support account key writes (skip Step 6)
QUIRK_NO_ACCOUNT_KEY = "QUIRK_NO_ACCOUNT_KEY"

# Device only responds to extended response format (0x10 flag)
QUIRK_EXTENDED_RESPONSE_ONLY = "QUIRK_EXTENDED_RESPONSE_ONLY"


# ==============================================================================
# KNOWN DEVICES DATABASE
# ==============================================================================
#
# Keys are model ID strings as emitted by the exploit chain: "0x<6 hex digits>"
# Values are dicts with:
#   name         - marketing name
#   manufacturer - brand/company
#   type         - earbuds | headphones | speaker
#   quirks       - list of QUIRK_* flag constants

KNOWN_DEVICES = {
    # ------------------------------------------------------------------
    # Google
    # ------------------------------------------------------------------
    "0x2C02A2": {
        "name": "Pixel Buds A-Series",
        "manufacturer": "Google",
        "type": "earbuds",
        "quirks": [],
    },
    "0x0A0175": {
        "name": "Pixel Buds Pro",
        "manufacturer": "Google",
        "type": "earbuds",
        "quirks": [QUIRK_EXTENDED_RESPONSE_ONLY],
    },
    "0x12A08E": {
        "name": "Pixel Buds Series-A (2nd Gen)",
        "manufacturer": "Google",
        "type": "earbuds",
        "quirks": [],
    },

    # ------------------------------------------------------------------
    # JBL
    # ------------------------------------------------------------------
    "0xD86164": {
        "name": "JBL Live Pro+ TWS",
        "manufacturer": "JBL",
        "type": "earbuds",
        "quirks": [QUIRK_NEEDS_SEEKER_ADDR],
    },
    "0x7174E6": {
        "name": "JBL Tour Pro 2",
        "manufacturer": "JBL",
        "type": "earbuds",
        "quirks": [QUIRK_NEEDS_SEEKER_ADDR, QUIRK_SLOW_GATT],
    },
    "0xF52494": {
        "name": "JBL Reflect Flow Pro",
        "manufacturer": "JBL",
        "type": "earbuds",
        "quirks": [QUIRK_MTU_83],
    },

    # ------------------------------------------------------------------
    # Sony
    # ------------------------------------------------------------------
    "0x2A96A4": {
        "name": "Sony WF-1000XM4",
        "manufacturer": "Sony",
        "type": "earbuds",
        "quirks": [QUIRK_SLOW_GATT, QUIRK_RETRY_CONNECT],
    },
    "0x1E89A3": {
        "name": "Sony WH-1000XM5",
        "manufacturer": "Sony",
        "type": "headphones",
        "quirks": [QUIRK_SLOW_GATT],
    },
    "0x6DC7AB": {
        "name": "Sony WF-1000XM5",
        "manufacturer": "Sony",
        "type": "earbuds",
        "quirks": [QUIRK_SLOW_GATT, QUIRK_EXTENDED_RESPONSE_ONLY],
    },

    # ------------------------------------------------------------------
    # Samsung
    # ------------------------------------------------------------------
    "0x82B0A4": {
        "name": "Galaxy Buds2 Pro",
        "manufacturer": "Samsung",
        "type": "earbuds",
        "quirks": [QUIRK_NEEDS_BONDING_FLAG],
    },
    "0x3C4152": {
        "name": "Galaxy Buds3 Pro",
        "manufacturer": "Samsung",
        "type": "earbuds",
        "quirks": [QUIRK_NEEDS_BONDING_FLAG, QUIRK_MTU_83],
    },
    "0x0E30D3": {
        "name": "Galaxy Buds Live",
        "manufacturer": "Samsung",
        "type": "earbuds",
        "quirks": [],
    },

    # ------------------------------------------------------------------
    # Bose
    # ------------------------------------------------------------------
    "0xB5D060": {
        "name": "Bose QuietComfort Earbuds II",
        "manufacturer": "Bose",
        "type": "earbuds",
        "quirks": [QUIRK_NO_ACCOUNT_KEY],
    },
    "0xF57D3A": {
        "name": "Bose QuietComfort 45",
        "manufacturer": "Bose",
        "type": "headphones",
        "quirks": [QUIRK_NO_ACCOUNT_KEY, QUIRK_SLOW_GATT],
    },

    # ------------------------------------------------------------------
    # Nothing
    # ------------------------------------------------------------------
    "0x4EC192": {
        "name": "Nothing Ear (2)",
        "manufacturer": "Nothing",
        "type": "earbuds",
        "quirks": [],
    },
    "0x7B3C6E": {
        "name": "Nothing Ear (1)",
        "manufacturer": "Nothing",
        "type": "earbuds",
        "quirks": [QUIRK_RETRY_CONNECT],
    },

    # ------------------------------------------------------------------
    # OnePlus
    # ------------------------------------------------------------------
    "0xC3A1D8": {
        "name": "OnePlus Buds Pro 2",
        "manufacturer": "OnePlus",
        "type": "earbuds",
        "quirks": [QUIRK_NEEDS_SEEKER_ADDR],
    },
    "0x9E5F2B": {
        "name": "OnePlus Buds 3",
        "manufacturer": "OnePlus",
        "type": "earbuds",
        "quirks": [],
    },

    # ------------------------------------------------------------------
    # Jabra
    # ------------------------------------------------------------------
    "0x5A7E9C": {
        "name": "Jabra Elite 10",
        "manufacturer": "Jabra",
        "type": "earbuds",
        "quirks": [QUIRK_MTU_83, QUIRK_SLOW_GATT],
    },
    "0x3F8B4D": {
        "name": "Jabra Elite 85t",
        "manufacturer": "Jabra",
        "type": "earbuds",
        "quirks": [QUIRK_MTU_83],
    },
}


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def lookup_device(model_id: str) -> dict | None:
    """Return the device entry for model_id, or None if not in the database.

    model_id must be in the canonical form produced by the exploit chain,
    e.g. "0x2C02A2" (hex digits are upper-case, six digits zero-padded).
    """
    if model_id is None:
        return None
    return KNOWN_DEVICES.get(model_id)


def get_quirks(model_id: str) -> list:
    """Return the list of quirk flags for model_id, or [] if unknown."""
    device = lookup_device(model_id)
    if device is None:
        return []
    return device.get("quirks", [])


def has_quirk(model_id: str, quirk: str) -> bool:
    """Return True if the device identified by model_id has the given quirk."""
    return quirk in get_quirks(model_id)
