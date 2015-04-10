# stdlib
require "uri"
require "openssl"
require "base64"

# urlsign
require "distack/urlsign/signer"
require "distack/urlsign/version"

module Distack
  module URLSign
    def self.strip_heredoc(string)
      min    = string.scan(/^[ \t]*(?=\S)/).min
      indent = min ? min.length : 0
      string.gsub(/^[ \t]{#{indent}}/, '')
    end
  end
end
