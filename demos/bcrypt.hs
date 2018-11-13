-- stack ghci --package text --package memory --package cryptonite --package bytestring --package exceptions --package time --ghci-options "-XOverloadedStrings"

{-# LANGUAGE GeneralizedNewtypeDeriving #-}

import Data.Text (Text)
import qualified Crypto.KDF.BCrypt as BCrypt
import qualified Data.Text.Encoding as TE
import Crypto.Random (MonadRandom)
import Control.Exception (Exception)
import Data.ByteArray (ByteArray, ByteArrayAccess)
import Data.Semigroup
import Control.Monad.Catch (MonadThrow, throwM)
import Data.ByteString (ByteString)

newtype HashedPassword = HashedPassword ByteString
  deriving (Eq, Show, Ord, ByteArray, Semigroup, Monoid, ByteArrayAccess)

-- Note: Recommended to lower this in test environments
bcryptCost :: Int
bcryptCost = 12

hashPassword :: MonadRandom m => Text -> m HashedPassword
hashPassword t = BCrypt.hashPassword bcryptCost (TE.encodeUtf8 t)

-- | Exception thrown if e.g. the Bcrypt hash is malformed
newtype PasswordCryptoError = PasswordCryptoError String
    deriving (Show)
instance Exception PasswordCryptoError

checkCorrectPassword :: MonadThrow m
                     => Text
                     -> HashedPassword
                     -> m Bool
checkCorrectPassword plaintext storedHash = do
  case BCrypt.validatePasswordEither (TE.encodeUtf8 plaintext) storedHash of
    Right isMatch -> return isMatch
    Left cryptoError -> throwM (PasswordCryptoError cryptoError)