-- stack ghci --package text --package memory --package cryptonite --package bytestring --package exceptions --package time --ghci-options "-XOverloadedStrings"

{-# LANGUAGE GeneralizedNewtypeDeriving #-}

import Control.Monad.IO.Class
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.ByteArray (ByteArrayAccess) -- memory package
import Data.ByteArray.Encoding (convertToBase, Base(Base32))
import Crypto.Random (MonadRandom(..))
import Data.ByteString (ByteString)
import Crypto.OTP
import Data.Time.Clock.POSIX

-- Secret Key to be stored in the database
newtype TOTPSecretKey = TOTPSecretKey ByteString
    deriving (Show, ByteArrayAccess)

-- The same secret key, encoded for Google Authenticator
newtype GoogleAuthenticatorEncodedKey = GoogleAuthenticatorEncodedKey Text
  deriving (Show)

randomTOTPSecretKey :: MonadRandom m => m (TOTPSecretKey, GoogleAuthenticatorEncodedKey)
randomTOTPSecretKey = do
  -- Google Authenticator accepts arbitrary length secrets, using 80 bits for its own services.
  -- RFC 4226 recommends a 160 bit (20 byte) secret key https://tools.ietf.org/html/rfc4226#section-4
  key <- getRandomBytes 20
  return (TOTPSecretKey key, googleAuthenticatorEncode key)

googleAuthenticatorEncode :: ByteString -> GoogleAuthenticatorEncodedKey
googleAuthenticatorEncode bs = GoogleAuthenticatorEncodedKey $ stripPadding $ TE.decodeUtf8 $ convertToBase Base32 bs
  where
    stripPadding t = T.dropWhileEnd (== '=') t

verifyTOTPPassword :: MonadIO m => TOTPSecretKey -> OTP -> m Bool
verifyTOTPPassword key code = do
    posixTime <- liftIO $ getPOSIXTime
    let otpTime = (floor posixTime :: OTPTime)

    return $ totpVerify defaultTOTPParams key otpTime code

-- otpauth://totp/demo?secret=LZIE3MRVVPTPYOE7PDL2JMXJAMJE577U&issuer=demo
-- https://www.qr-code-generator.com/