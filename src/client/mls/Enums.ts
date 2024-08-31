/**
 * The source of a leaf node, internally a uint8.
 */
enum LeafNodeSource {
    reserved = 0,
    key_package = 1,
    update = 2,
    commit = 3
}

/**
 * The credential type, internally a uint16.
 */
enum CredentialType {
    RESERVED = 0x0000,
    basic = 0x0001,
    x509 = 0x0002,
}

/**
 * Extension types for users, internally a uint16.
 */
enum ExtensionType {
    RESERVED = 0x0000,
    application_id = 0x0001,
    ratchet_tree = 0x0002,
    required_capabilities = 0x0003,
    external_pub = 0x0004,
    external_senders = 0x0005,
}

/**
 * Protocol versions for MLS messages, internally a uint16.
 */
enum ProtocolVersion {
    reserved = 0,
    mls10 = 1
}

/**
 * Content types for MLS messages, internally a uint8.
 */
enum ContentType {
    reserved = 0,
    application = 1,
    proposal = 2,
    commit = 3
}

/**
 * Sender types for MLS messages, internally a uint8.
 */
enum SenderType {
    reserved = 0,
    member = 1,
    external = 2,
    new_member_proposal = 3,
    new_member_commit = 4
}

/**
 * Wire formats for MLS messages, internally a uint16.
 */
enum WireFormat {
    RESERVED = 0x0000,
    mls_public_message = 0x0001,
    mls_private_message = 0x0002,
    mls_welcome = 0x0003,
    mls_group_info = 0x0004,
    mls_key_package = 0x0005
}

/**
 * Cipher suite types supported by MLS, internally a uint16.
 */
enum CipherSuiteType {
    RESERVED = 0x0000,
    MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,
    MLS_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002,
    MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,
    MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 0x0004,
    MLS_256_DHKEMP521_AES256GCM_SHA512_P521 = 0x0005,
    MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006,
    MLS_256_DHKEMP384_AES256GCM_SHA384_P384 = 0x0007,
}

/**
 * Proposal types for MLS messages, internally a uint16.
 */
enum ProposalType {
    RESERVED = 0x0000,
    add = 0x0001,
    update = 0x0002,
    remove = 0x0003,
    psk = 0x0004,
    reinit = 0x0005,
    external_init = 0x0006,
    group_context_extension = 0x0007,
}

enum ProposalOrRefType {
    reserved = 0,
    proposal = 1,
    reference = 2
}

export { ProtocolVersion, ContentType, SenderType, WireFormat, CipherSuiteType, ProposalType, ProposalOrRefType, ExtensionType, LeafNodeSource, CredentialType };