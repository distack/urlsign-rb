module Distack::URLSign
  InvalidSignatureError = Class.new(StandardError)

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

      chunks = [url.scheme, "#{url.host}:#{url.port}", url.path, url.query, url.userinfo].compact
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

      original_q  = q.dup
      original_q.delete("_signature")

      original_qs = Rack::Utils.build_nested_query(original_q)

      chunks = [url.scheme, "#{url.host}:#{url.port}", url.path, original_qs, url.userinfo].compact
      digest = OpenSSL::Digest.new("sha512")

      rawsig    = OpenSSL::HMAC.digest(digest, @key, chunks.join)
      signature = Base64.urlsafe_encode64(rawsig)

      if signature == q["_signature"]
        new_url = url.dup
        new_url.query = original_qs
        new_url
      else
        raise InvalidSignatureError, "signature is invalid for #{url}"
      end
    end
  end
end
