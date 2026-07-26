package io.registry.esignet.relay.relay;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.regex.Pattern;

/**
 * Reads a reloadable Relay bearer credential from a file.
 *
 * <p>The path is the only retained state. Every call reopens the file so an atomic secret-file
 * replacement takes effect on the next Relay request. Failure details deliberately omit both the
 * configured path and file content.
 */
final class RelayBearerTokenFile {

  /** Large enough for API keys and access tokens while bounding every credential read. */
  static final int MAX_TOKEN_BYTES = 16 * 1024;

  private static final Pattern BEARER_TOKEN =
      Pattern.compile("[A-Za-z0-9\\-._~+/]+=*");

  private final Path path;

  RelayBearerTokenFile(String configuredPath) {
    try {
      Path parsed = Path.of(configuredPath);
      if (!parsed.isAbsolute()) {
        throw new IllegalArgumentException(
            "registry.relay.auth.bearer-token-file must be an absolute path");
      }
      this.path = parsed.normalize();
    } catch (InvalidPathException | NullPointerException e) {
      throw new IllegalArgumentException(
          "registry.relay.auth.bearer-token-file must be an absolute path");
    }
  }

  String read() throws CredentialException {
    try {
      BasicFileAttributes attributes =
          Files.readAttributes(path, BasicFileAttributes.class);
      if (!attributes.isRegularFile() || attributes.size() > MAX_TOKEN_BYTES) {
        throw new CredentialException();
      }

      byte[] bytes;
      try (InputStream input = Files.newInputStream(path)) {
        bytes = input.readNBytes(MAX_TOKEN_BYTES + 1);
      }
      if (bytes.length == 0 || bytes.length > MAX_TOKEN_BYTES) {
        throw new CredentialException();
      }

      String token = decodeUtf8(bytes);
      if (token.endsWith("\r\n")) {
        token = token.substring(0, token.length() - 2);
      } else if (token.endsWith("\n")) {
        token = token.substring(0, token.length() - 1);
      }
      if (!BEARER_TOKEN.matcher(token).matches()) {
        throw new CredentialException();
      }
      return token;
    } catch (CredentialException e) {
      throw e;
    } catch (IOException | SecurityException e) {
      throw new CredentialException();
    }
  }

  private static String decodeUtf8(byte[] bytes) throws CredentialException {
    try {
      return StandardCharsets.UTF_8
          .newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(bytes))
          .toString();
    } catch (CharacterCodingException e) {
      throw new CredentialException();
    }
  }

  /** Sanitized failure that carries neither the credential path nor its content. */
  static final class CredentialException extends Exception {
    CredentialException() {
      super("Relay bearer credential is unavailable or invalid");
    }
  }
}
