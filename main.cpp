#include <string>
#include <iostream>

#include <google_auth_export_decoder.hpp>

int
main (int argc, char *argv[])
{
  using namespace google_auth_export_decoder;

  if (argc != 2)
    {
      std::cerr << "Enter the URI from google authenticator QR code"
	  << std::endl;
      std::cerr << "The URI looks like otpauth-migration://offline?data=..."
	  << std::endl;

      return 1;
    }

  const std::string input (argv[1]);
  GoogleAuthenticatorExportDecoder dec (input);
  const bool parseOk = dec.parseInput ();

  if (parseOk)
    {
      bool is_first = true;
      std::cout << "[\n";
      for (auto &otp_params : dec.getOtpParametersList ())
	{
	  if (is_first)
	    {
	      is_first = false;
	    }
	  else
	    {
	      std::cout << ",\n";
	    }

	  std::cout << "  {" << "\n";
	  std::cout << "    \"name\" : \"" << otp_params.getName () << "\",\n";
	  std::cout << "    \"issuer\" : \"" << otp_params.getIssuer ()
	      << "\",\n";
	  std::cout << "    \"algorithm\" : \"" << otp_params.getAlgorithm ()
	      << "\",\n";
	  std::cout << "    \"digits\" : \"" << otp_params.getNumDigits ()
	      << "\",\n";
	  std::cout << "    \"type\" : \"" << otp_params.getType () << "\",\n";
	  std::cout << "    \"secret\" : \"" << otp_params.getOtpSecret ()
	      << "\"\n";
	  std::cout << "  }";
	}
      std::cout << "\n]" << std::endl;

      return 0;
    }
  else
    {
      std::cerr << "Enter the URI from google authenticator QR code"
	  << std::endl;
      std::cerr << "The URI looks like otpauth-migration://offline?data=..."
	  << std::endl;

      return 1;
    }
}
