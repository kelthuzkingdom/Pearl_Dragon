# Add to ActionType enum
INTELLIGENCE_GATHERING = "intelligence_gathering"
COUNTER_SURVEILLANCE = "counter_surveillance"
def legal_compliance_check(target_ip, operation_type):
    """
    REQUIRED: Validate operation legality
    """
    legal_targets = [
        "192.168.1.0/24",    # Your test network
        "10.0.0.0/24",       # Your lab network
        "localhost",          # Local testing
        "127.0.0.1"          # Loopback
    ]

    if not any(target_ip.startswith(net) for net in legal_targets):
        raise PermissionError(f"ILLEGAL TARGET: {target_ip}")

    return True
