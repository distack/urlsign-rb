require_relative 'minitest_helper'

class Distack::URLSignTest < Minitest::Test
  def test_that_it_has_a_version_number
    refute_nil ::Distack::URLSign::VERSION
  end

  def test_sign_verify_with_query_string
    url = URI.parse("http://foo.test/path?search=john&fields[]=name&fields[]=age")
    key = "a1b2c3d4f5"

    signer = Distack::URLSign::Signer.new(key)
    signed_url = signer.sign(url)
    assert_equal signer.verify(signed_url), url
  end

  def test_sign_valid_without_query_string
    url = URI.parse("http://foo.test:3000/search")
    key = "a1b2c3d4f5"

    signer = Distack::URLSign::Signer.new(key)
    signed_url = signer.sign(url).to_s
    assert_equal true, signer.valid?(URI.parse(signed_url))
  end

  def test_valid
    url = URI.parse("http://foo.test:3000/path?search")
    key = "a1b2c3d4f5"

    signer = Distack::URLSign::Signer.new(key)
    signed_url = signer.sign(url)


    assert_equal signer.valid?(url), false
    assert_equal signer.valid?(signed_url), true
  end
end
