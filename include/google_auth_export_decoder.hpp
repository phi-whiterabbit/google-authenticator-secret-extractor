#ifndef GOOGLE_AUTHENTICATOR_SECRETS_EXTRACTOR_HPP_
#define GOOGLE_AUTHENTICATOR_SECRETS_EXTRACTOR_HPP_

#include <string>
#include <memory>
#include <vector>

namespace google_auth_export_decoder
{
  enum class OtpAlgorithm
  {
    UNSPECIFIED, SHA1, SHA256, SHA512, MD5
  };

  std::ostream&
  operator<< (std::ostream &os, const OtpAlgorithm &otp_algorithm);

  enum class OtpType
  {
    UNSPECIFIED, HOTP, TOTP
  };

  std::ostream&
  operator<< (std::ostream &os, const OtpType &otp_type);

  class OtpParameters
  {
  public:
    OtpParameters ();
    ~OtpParameters ();

    OtpParameters (OtpParameters &&rhs) noexcept;
    OtpParameters&
    operator= (OtpParameters &&rhs) noexcept;
    OtpParameters (const OtpParameters &rhs);
    OtpParameters&
    operator= (const OtpParameters &rhs);

    /**
     * Returns the name.
     */
    const std::string&
    getName () const;

    /**
     * Sets the name.
     */
    void
    setName (const std::string &name);

    /**
     * Returns the issuer.
     */
    const std::string&
    getIssuer () const;

    /**
     * Sets the issuer.
     */
    void
    setIssuer (const std::string &issuer);

    /**
     * Returns the algorithm.
     */
    const OtpAlgorithm&
    getAlgorithm () const;

    /**
     * Sets the algorithm.
     */
    void
    setAlgorithm (const OtpAlgorithm &otp_algorithm);

    /**
     * Returns the number of digits.
     */
    int
    getNumDigits () const;

    /**
     * Sets the number of digits.
     */
    void
    setNumDigits (int num_digits);

    /**
     * Returns the OTP type.
     */
    const OtpType&
    getType () const;

    /**
     * Sets the OTP type.
     */
    void
    setType (const OtpType &otp_type);

    /**
     * Returns the OTP secret.
     */
    const std::string&
    getOtpSecret () const;

    /**
     * Sets the OTP secret.
     */
    void
    setOtpSecret (const std::string &secret);

  private:
    class Impl;
    std::unique_ptr<Impl> m_pimpl;
  };

  class GoogleAuthenticatorExportDecoder
  {
  public:
    /**
     * Call this constructor with the input data as exported by the
     * google authenticator via a QR code.
     *
     * @param input the string containing the data from the QR code
     */
    GoogleAuthenticatorExportDecoder (const std::string &input);

    ~GoogleAuthenticatorExportDecoder ();

    /**
     * Reads the input data and returns true, if parsed successfully,
     * false otherwise.
     *
     * @return true when parsed successfully, false otherwise
     */
    bool
    parseInput ();

    /**
     * Returns a list of OtpParameters.
     */
    const std::vector<OtpParameters>&
    getOtpParametersList () const;

  private:
    class Impl;
    std::unique_ptr<Impl> m_pimpl;
  };
} // namespace google_auth_export_decoder

#endif /* GOOGLE_AUTHENTICATOR_SECRETS_EXTRACTOR_HPP_ */
