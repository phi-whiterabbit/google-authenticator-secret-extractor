#include "google_auth_export_decoder.hpp"

#include <map>
#include <algorithm>
#include <utility>
#include <ostream>
#include <iostream>
#include <uriparser/Uri.h>
#include <cppcodec/base64_rfc4648.hpp>
#include <cppcodec/base32_rfc4648.hpp>
#include <google_auth.pb.h>

namespace google_auth_export_decoder
{
  class OtpParameters::Impl
  {
  public:
    Impl () :
	m_name (""), m_issuer (""), m_otp_algorithm (OtpAlgorithm::UNSPECIFIED), m_num_digits (
	    0), m_otp_type (OtpType::UNSPECIFIED), m_secret ("")
    {
    }

    Impl (const Impl &rhs) :
	m_name (rhs.getName ()), m_issuer (rhs.getIssuer ()), m_otp_algorithm (
	    rhs.getAlgorithm ()), m_num_digits (rhs.getNumDigits ()), m_otp_type (
	    rhs.getType ()), m_secret (rhs.getOtpSecret ())
    {
    }

    const std::string&
    getName () const
    {
      return m_name;
    }

    const std::string&
    getIssuer () const
    {
      return m_issuer;
    }

    const OtpAlgorithm&
    getAlgorithm () const
    {
      return m_otp_algorithm;
    }

    int
    getNumDigits () const
    {
      return m_num_digits;
    }

    const OtpType&
    getType () const
    {
      return m_otp_type;
    }

    const std::string&
    getOtpSecret () const
    {
      return m_secret;
    }

    void
    setName (const std::string &name)
    {
      m_name = name;
    }

    void
    setIssuer (const std::string &issuer)
    {
      m_issuer = issuer;
    }

    void
    setAlgorithm (const OtpAlgorithm &otp_algorithm)
    {
      m_otp_algorithm = otp_algorithm;
    }

    void
    setNumDigits (int num_digits)
    {
      m_num_digits = num_digits;
    }

    void
    setType (const OtpType &otp_type)
    {
      m_otp_type = otp_type;
    }

    void
    setOtpSecret (const std::string &secret)
    {
      m_secret = secret;
    }

  private:
    std::string m_name;
    std::string m_issuer;
    OtpAlgorithm m_otp_algorithm;
    int m_num_digits;
    OtpType m_otp_type;
    std::string m_secret;
  };

  std::ostream&
  operator << (std::ostream &os, const OtpAlgorithm &otp_algorithm)
  {
    switch (otp_algorithm)
      {
      case OtpAlgorithm::UNSPECIFIED:
	os << "UNSPECIFIED";
	break;
      case OtpAlgorithm::SHA1:
	os << "SHA1";
	break;
      case OtpAlgorithm::SHA256:
	os << "SHA256";
	break;
      case OtpAlgorithm::SHA512:
	os << "SHA512";
	break;
      case OtpAlgorithm::MD5:
	os << "MD5";
	break;
      }

    return os;
  }

  std::ostream&
  operator << (std::ostream &os, const OtpType &otp_type)
  {
    switch (otp_type)
      {
      case OtpType::UNSPECIFIED:
	os << "UNSPECIFIED";
	break;
      case OtpType::HOTP:
	os << "HOTP";
	break;
      case OtpType::TOTP:
	os << "TOTP";
	break;
      }

    return os;
  }

  namespace detail
  {
    static inline std::string&
    ltrim (std::string &str)
    {
      str.erase (str.begin (), std::find_if (str.begin (), str.end (), []
      (unsigned char c)
	{ return !std::isspace(c);}));
      return str;
    }

    static inline std::string&
    rtrim (std::string &str)
    {
      str.erase (std::find_if (str.rbegin (), str.rend (), []
      (unsigned char c)
	{ return !std::isspace(c);}).base (),
		 str.end ());
      return str;
    }

    static inline std::string
    createTrimmedString (const std::string &str)
    {
      std::string trimmed (str);

      ltrim (trimmed);
      rtrim (trimmed);

      return trimmed;
    }

    class Uriparser
    {
    public:
      Uriparser (const std::string &uri) :
	  m_uri (), m_moved_from (false), m_parse_status (URI_SUCCESS), m_errorPos (
	      0)
      {
	m_parse_status = uriParseSingleUriA (&m_uri, uri.c_str (), &m_errorPos);
      }

      Uriparser (const Uriparser &rhs) = delete;
      Uriparser&
      operator= (const Uriparser &rhs) = delete;

      Uriparser (Uriparser &&rhs) noexcept :
	  m_uri (), m_moved_from (false), m_parse_status (rhs.m_parse_status), m_errorPos (
	      rhs.m_errorPos)
      {
	m_uri = rhs.m_uri;
	rhs.m_moved_from = true;
      }

      Uriparser&
      operator= (Uriparser &&rhs)
      {
	if (this != &rhs)
	  {
	    if (!m_moved_from)
	      {
		uriFreeUriMembersA (&m_uri);
	      }
	    m_uri = rhs.m_uri;
	    rhs.m_moved_from = true;
	    m_moved_from = false;
	    m_parse_status = rhs.m_parse_status;
	    m_errorPos = rhs.m_errorPos;
	  }

	return *this;
      }

      ~Uriparser ()
      {
	if (!m_moved_from)
	  {
	    uriFreeUriMembersA (&m_uri);
	  }
      }

      bool
      parseOk ()
      {
	return m_parse_status == URI_SUCCESS;
      }

      std::map<std::string, std::string>
      getQuery ()
      {
	std::map<std::string, std::string> query;

	UriQueryListA *query_list;
	int item_count;

	if (uriDissectQueryMallocA (&query_list, &item_count, m_uri.query.first,
				    m_uri.query.afterLast) == URI_SUCCESS)
	  {
	    if (item_count > 0)
	      {
		query.emplace (query_list->key, query_list->value);
		while (query_list->next)
		  {
		    query_list = query_list->next;
		    query.emplace (query_list->key, query_list->value);
		  }
	      }
	    uriFreeQueryListA (query_list);
	  }

	return query;
      }

    private:
      UriUriA m_uri;
      bool m_moved_from;
      int m_parse_status;
      const char *m_errorPos;
    }
    ;
  } // namespace detail

  class GoogleAuthenticatorExportDecoder::Impl
  {
  public:
    Impl (const std::string &input) :
	m_input (detail::createTrimmedString (input)), m_otp_parameter_list ()
    {
    }

    bool
    parseInput ()
    {
      using base32 = cppcodec::base32_rfc4648;
      using base64 = cppcodec::base64_rfc4648;

      detail::Uriparser uriparser (m_input);
      if (!uriparser.parseOk ())
	{
	  return false;
	}

      auto query = uriparser.getQuery ();
      auto search_data = query.find ("data");
      if (search_data == query.end ())
	{
	  return false;
	}

      const std::string &payload_base64_encoded = search_data->second;
      const std::string decoded (
	  base64::decode<std::string> (payload_base64_encoded));

      MigrationPayload migration_payload;
      bool parse_ok = migration_payload.ParseFromString (decoded);
      if (!parse_ok)
	{
	  return false;
	}

      for (const MigrationPayload_OtpParameters &proto_opt_params : migration_payload.otp_parameters ())
	{
	  OtpParameters opt_params;
	  opt_params.setName (proto_opt_params.name ());
	  opt_params.setIssuer (proto_opt_params.issuer ());
	  switch (proto_opt_params.algorithm ())
	    {
	    case MigrationPayload_Algorithm_ALGORITHM_SHA1:
	      opt_params.setAlgorithm (OtpAlgorithm::SHA1);
	      break;
	    case MigrationPayload_Algorithm_ALGORITHM_SHA256:
	      opt_params.setAlgorithm (OtpAlgorithm::SHA256);
	      break;
	    case MigrationPayload_Algorithm_ALGORITHM_SHA512:
	      opt_params.setAlgorithm (OtpAlgorithm::SHA512);
	      break;
	    case MigrationPayload_Algorithm_ALGORITHM_MD5:
	      opt_params.setAlgorithm (OtpAlgorithm::MD5);
	      break;
	    default:
	      opt_params.setAlgorithm (OtpAlgorithm::UNSPECIFIED);
	      break;
	    }
	  switch (proto_opt_params.digits ())
	    {
	    case MigrationPayload_DigitCount_DIGIT_COUNT_SIX:
	      opt_params.setNumDigits (6);
	      break;
	    case MigrationPayload_DigitCount_DIGIT_COUNT_EIGHT:
	      opt_params.setNumDigits (8);
	      break;
	    default:
	      opt_params.setNumDigits (0);
	      break;
	    }
	  switch (proto_opt_params.type ())
	    {
	    case MigrationPayload_OtpType_OTP_TYPE_HOTP:
	      opt_params.setType (OtpType::HOTP);
	      break;
	    case MigrationPayload_OtpType_OTP_TYPE_TOTP:
	      opt_params.setType (OtpType::TOTP);
	      break;
	    default:
	      opt_params.setType (OtpType::UNSPECIFIED);
	      break;
	    }
	  const std::string base32_enc_secret (
	      base32::encode<std::string> (proto_opt_params.secret ()));
	  opt_params.setOtpSecret (base32_enc_secret);

	  m_otp_parameter_list.push_back (std::move (opt_params));
	}

      return true;
    }

    const std::vector<OtpParameters>&
    getOtpParametersList () const
    {
      return m_otp_parameter_list;
    }

  private:
    const std::string m_input;
    std::vector<OtpParameters> m_otp_parameter_list;
  };

  OtpParameters::OtpParameters () :
      m_pimpl (new Impl ())
  {
  }

  OtpParameters::~OtpParameters () = default;

  OtpParameters::OtpParameters (OtpParameters&&) noexcept = default;
  OtpParameters&
  OtpParameters::operator= (OtpParameters&&) noexcept = default;

  OtpParameters::OtpParameters (const OtpParameters &rhs) :
      m_pimpl (new Impl (*rhs.m_pimpl))
  {
  }

  OtpParameters&
  OtpParameters::operator= (const OtpParameters &rhs)
  {
    if (this != &rhs)
      m_pimpl.reset (new Impl (*rhs.m_pimpl));

    return *this;
  }

  const std::string&
  OtpParameters::getName () const
  {
    return m_pimpl->getName ();
  }

  void
  OtpParameters::setName (const std::string &name)
  {
    m_pimpl->setName (name);
  }

  const std::string&
  OtpParameters::getIssuer () const
  {
    return m_pimpl->getIssuer ();
  }

  void
  OtpParameters::setIssuer (const std::string &issuer)
  {
    m_pimpl->setIssuer (issuer);
  }

  const OtpAlgorithm&
  OtpParameters::getAlgorithm () const
  {
    return m_pimpl->getAlgorithm ();
  }

  void
  OtpParameters::setAlgorithm (const OtpAlgorithm &otp_algorithm)
  {
    m_pimpl->setAlgorithm (otp_algorithm);
  }

  int
  OtpParameters::getNumDigits () const
  {
    return m_pimpl->getNumDigits ();
  }

  void
  OtpParameters::setNumDigits (int num_digits)
  {
    m_pimpl->setNumDigits (num_digits);
  }

  const OtpType&
  OtpParameters::getType () const
  {
    return m_pimpl->getType ();
  }

  void
  OtpParameters::setType (const OtpType &otp_type)
  {
    m_pimpl->setType (otp_type);
  }

  const std::string&
  OtpParameters::getOtpSecret () const
  {
    return m_pimpl->getOtpSecret ();
  }

  void
  OtpParameters::setOtpSecret (const std::string &secret)
  {
    m_pimpl->setOtpSecret (secret);
  }

  GoogleAuthenticatorExportDecoder::GoogleAuthenticatorExportDecoder (
      const std::string &input) :
      m_pimpl (new Impl (input))
  {
  }

  GoogleAuthenticatorExportDecoder::~GoogleAuthenticatorExportDecoder () = default;

  bool
  GoogleAuthenticatorExportDecoder::parseInput ()
  {
    return m_pimpl->parseInput ();
  }

  const std::vector<OtpParameters>&
  GoogleAuthenticatorExportDecoder::getOtpParametersList () const
  {
    return m_pimpl->getOtpParametersList ();
  }

} // namespace google_auth_export_decoder
