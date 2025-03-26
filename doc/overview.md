# Introduction to libcdoc

The libcdoc project is an open-source C++ library designed for handling CDoc (Cryptographic Document) containers, a format used for secure document encryption. While CDoc containers are a component of secure digital workflows, libcdoc specifically focuses on the encryption and decryption of these containers rather than digital signatures.

CDoc containers are utilized in Estonia for secure document exchange, especially in contexts where confidentiality is critical. The libcdoc library enables applications to create, parse, and decrypt encrypted CDoc containers, ensuring secure access to sensitive content.

## Key Features

- Support for CDoc Versions: Handles CDoc 1.0 and 1.1 formats (CDoc 1.0, CDoc 1.1) as well as CDoc 2.0 (CDoc 2.0 Specification).

- Future-Proof Design: Includes support for workflows based on current and upcoming standard changes (CDoc 2.0 Draft), ensuring compatibility with evolving requirements.

- Encryption Support: Provides functionality for encrypting and decrypting documents securely, including both online and offline decryption workflows.

- Extended Encryption Schemes: Supports password-based encryption/decryption schemes, Smart-ID/Mobile-ID based encryption and decryption, as well as ID-card/smartcard encryption and other additional hardware security tokens.

- Integration with eID Systems: Can be used alongside other components in the Estonian ID-card infrastructure, although it does not handle digital signatures.

## Use Cases

- Applications requiring secure encrypted document handling.

- Services involving confidential document exchange.

- Integration with digital identity systems for secure communication.

## Licensing and Contributions

libcdoc is licensed under the LGPL, allowing it to be used in both open-source and proprietary software. Contributions are welcome via pull requests on GitHub.

This library plays a key role in enabling confidential digital document workflows in Estonia and can serve as a model for implementing similar secure container formats in other systems.

## Library Architecture

The libcdoc library is structured around modular and extensible components that handle various aspects of CDoc container processing. The design emphasizes maintainability and flexibility to accommodate evolving standards and security requirements.

### Core Components

- CDocReader/CDocWriter: Responsible for reading and writing CDoc 1.x and 2.0 containers. It supports parsing XML-based metadata and managing encrypted payloads.

- Encryption Engine: Handles encryption and decryption using cryptographic libraries such as OpenSSL. It supports a variety of schemes including public key encryption (smartcards, ID-cards, Mobile-ID, Smart-ID), symmetric password-based encryption, and hybrid encryption models.

- Recipient Management: Implements recipient-specific key wrapping and metadata handling for multi-recipient encrypted documents.

- Workflow Support: Enables both online and offline workflows, supporting scenarios where keys are available via connected tokens or remote signing/encryption services.

- Standards Abstraction: Provides an abstraction layer for handling differences between CDoc versions and upcoming specification changes.

### Extensibility

The architecture is designed to allow easy integration of new encryption backends and recipient schemes. For instance, support for emerging mobile and cloud-based identity systems can be added without restructuring core functionality.

## Interoperability

libcdoc maintains strong compatibility with other components in the Estonian eID ecosystem and adheres closely to official specifications to ensure interoperability across different platforms and implementations.

This architectural foundation ensures that libcdoc remains a reliable and future-ready library for secure document encryption in both governmental and private sector applications.