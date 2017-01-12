module Distack::URLSign
  InvalidSignatureError = Class.new(StandardError)
  MissingSignatureError = Class.new(StandardError)


  class Signer
    KEY_REGEX = /^[0-9A-f]+$/

    def initialize(hex_key)
      if hex_key !~ KEY_REGEX
        raise "key is not valid hex string"
      end

      @key = [hex_key].pack("H*")
    end

    def sign(url)
      if url.opaque
        raise "can't sign opaque URL"
      end

      host_with_port = url.port == url.default_port ? url.host : "#{url.host}:#{url.port}"
      chunks = [url.scheme, host_with_port, url.path, url.query, url.userinfo].compact
      digest = OpenSSL::Digest.new("sha512")

      rawsig    = OpenSSL::HMAC.digest(digest, @key, chunks.join)
      signature = Base64.urlsafe_encode64(rawsig)

      if url.query
        q = Rack::Utils.parse_nested_query(url.query)
      else
        q = {}
      end

      q ["_signature"] = signature

      new_url = url.dup
      new_url.query = Rack::Utils.build_nested_query(q)
      new_url
    end

    def verify(url)
      if url.opaque
        raise "can't verify opaque URL"
      end

      q = Rack::Utils.parse_nested_query(url.query)
      raise MissingSignatureError unless q["_signature"]

      original_q  = q.dup
      original_q.delete("_signature")

      original_qs = Rack::Utils.build_nested_query(original_q)

      host_with_port = url.port == url.default_port ? url.host : "#{url.host}:#{url.port}"
      chunks = [url.scheme, host_with_port, url.path, original_qs, url.userinfo].compact
      digest = OpenSSL::Digest.new("sha512")

      rawsig    = OpenSSL::HMAC.digest(digest, @key, chunks.join)
      signature = Base64.urlsafe_encode64(rawsig)

      if secure_compare(signature, q["_signature"])
        new_url = url.dup
        new_url.query = original_qs
        new_url
      else
        raise InvalidSignatureError, "signature is invalid for #{url}"
      end
    end

    private

    # Constant time string comparison.
    #
    # The values compared should be of fixed length, such as strings
    # that have already been processed by HMAC. This should not be used
    # on variable length plaintext strings because it could leak length info
    # via timing attacks.
    #
    # Copied from ActiveSupport
    #
    # https://github.com/rails/rails/blob/036bbda9eb3b3885223d53646777733a1547d89a/activesupport/lib/active_support/security_utils.rb#L11-L19
    def secure_compare(a, b)
      return false unless a.bytesize == b.bytesize

      l = a.unpack "C#{a.bytesize}"

      res = 0
      b.each_byte { |byte| res |= byte ^ l.shift }
      res == 0
    end
  end
end
