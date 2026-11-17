# frozen_string_literal: true

require_relative "support"

# Edge-case tokens and the reason the Python SDK gives each, read with PyJWT. The Ruby
# SDK must give every one the same reason. test/fixtures/pyjwt_parity.py writes the
# file; run it again after a change to PyJWT or to the Python SDK.
class PyjwtParityTest < Minitest::Test
  include Support

  FIXTURE = JSON.parse(File.read(File.join(__dir__, "fixtures", "pyjwt_parity.json")))

  def test_the_fixture_holds_only_a_public_key
    refute FIXTURE["key"].key?("d")
    refute_includes File.read(File.join(__dir__, "fixtures", "pyjwt_parity.json")), "PRIVATE KEY"
  end

  def test_every_token_gets_the_reason_the_python_sdk_gives
    pair = KeyPair.new(FIXTURE["key"]["kid"], nil, FIXTURE["key"])
    issuer = FakeIssuer.new(pair, issuer: FIXTURE["issuer"])
    verifier = Keelie::TokenVerifier.new(FIXTURE["issuer"], FIXTURE["audience"], FIXTURE["org_id"],
                                         keys: Keelie::SigningKeys.new(FIXTURE["issuer"], http: issuer))
    differ = FIXTURE["cases"].filter_map do |test|
      expected = test["reason"]&.to_sym
      actual = begin
        verifier.verify(test["token"])
        nil
      rescue Keelie::TokenRejected => e
        e.reason
      end
      "#{test["name"]}: Python #{expected.inspect}, Ruby #{actual.inspect}" unless actual == expected
    end
    assert_empty differ, "PyJWT #{FIXTURE["pyjwt"]} on Python #{FIXTURE["python"]}"
    assert_operator FIXTURE["cases"].size, :>=, 100
  end
end
