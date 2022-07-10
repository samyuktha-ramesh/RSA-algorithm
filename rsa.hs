import Control.Monad (replicateM)
import Data.Char
import Data.List
import Data.Ratio (numerator)
import Data.Sequence (chunksOf)
import Debug.Trace
import System.Environment (getArgs)
import System.Random
import Text.ParserCombinators.ReadP (string)

-- (b^p) mod m
modPower :: Integer -> Integer -> Integer -> Integer
modPower _ _ 1 = 0
modPower _ 0 _ = 1
modPower b 1 m = b `mod` m
modPower b p m = if even p then (modPower b (p `div` 2) m ^ 2) `mod` m else mod (modPower b (div (p-1) 2) m ^ 2 * b) m

-- x = 2^s*r, r is odd
f :: Integer -> (Integer, Integer)
f x = g x 0
    where g x s = if odd x then (s,x) else g (x `div` 2) (s+1)

getRandomNumber :: Integer -> Integer -> IO Integer
getRandomNumber lo hi = randomRIO (lo, hi)

getWitnesses :: Integer -> IO [Integer]
getWitnesses n = do replicateM 60 (getRandomNumber 2 (n-1))

-- check if w is a witness for n being composite
isWitness :: Integer -> Integer -> Bool
isWitness n w = y /= 1 && y /= (n-1) && notElem (n-1) squares
    where
        (s,r) = f (n-1)
        y = modPower w r n
        squares = take 20 (iterate (\x -> (x^2) `mod` n) ((y^2) `mod` n))

isPrime :: Integer -> IO Bool
isPrime n
    | n == 2 = return True
    | n <= 1 || even n = return False
    | otherwise = do
        -- witnesses <- take 50 . randomRs (2,n-1) <$> newStdGen
        witnesses <- getWitnesses n
        return (not (any (isWitness n) witnesses))

--gets a random large prime number
getRandomPrime :: IO Integer
getRandomPrime = do
    x <- getRandomNumber (10^156) (10^157)
    prime <- isPrime x
    if prime then return x else getRandomPrime

-- get the 'e' part of the public RSA key (e,n)
getPub :: Integer -> Integer -> IO Integer
getPub p q = do
    e <- getRandomNumber 2 (prod-1)
    if gcd e prod == 1 then return e
    else getPub p q
    where
        prod = (p-1) * (q-1)

-- extended Euclid's algorithm with only the last two elements returned instead of all three
extEuclidsAlg :: Integer -> Integer -> (Integer, Integer)
extEuclidsAlg a 0 = (1, 0)
extEuclidsAlg a b = (y, x-q*y)
    where
        q = a `div` b
        r = a `mod` b
        (x,y) = extEuclidsAlg b r

-- get the 'd' part of the private RSA key (d,n) using the 'e' of the public RSA key
getPriv :: Integer -> Integer -> Integer -> IO Integer
getPriv e p q = return (firstEuclid `mod` prod)
    where
        prod = (p-1) * (q-1)
        firstEuclid = fst (extEuclidsAlg e prod)

getKeyPairs :: IO String
getKeyPairs = do
    p <- getRandomPrime
    q <- getRandomPrime
    e <- getPub p q
    d <- getPriv e p q
    let prod = p * q
    writeFile "pub.key" (unlines [show e, show prod])
    writeFile "priv.key" (unlines [show d, show prod])
    return "Keys written to files"

splitText :: String -> [String]
splitText [] = []
splitText text = first : splitText rest
    where first = take 64 text
          rest = drop 64 text

textToInteger :: String -> Integer
textToInteger [] = 0
textToInteger (x:xs) = toInteger (ord x) + (128 * textToInteger xs)

integerToText :: Integer -> String
integerToText 0 = []
integerToText x = chr (fromInteger (x `mod` 128)) : integerToText (x `div` 128)

encryptHelper :: (Integer, Integer) -> Integer -> Integer
encryptHelper (e,n) x = modPower x e n

decryptHelper :: (Integer, Integer) -> Integer -> Integer
decryptHelper (d,n) x = modPower x d n

encrypt :: String -> (Integer, Integer) -> String
encrypt txt (e, n) = show x
    where y = map textToInteger (splitText txt)
          x = map (encryptHelper (e,n)) y

decrypt :: String -> (Integer, Integer) -> String
decrypt nums (d, n) = concat x
    where y = map (decryptHelper (d,n)) (read nums :: [Integer])
          x = map integerToText y

startEncryption :: String -> String -> String -> IO String
startEncryption keyFile inputFile outputFile = do
    contents <- readFile keyFile
    doc <- readFile inputFile
    let
        [es, ns] = lines contents
        e = read es
        n = read ns
    writeFile outputFile (encrypt doc (e,n))
    return ("Encrypted document written to file " ++ outputFile)


startDecryption :: String -> String -> IO String
startDecryption keyFile docFile= do
    contents <- readFile keyFile
    doc <- readFile docFile
    let
        [ds, ns] = lines contents
        d = read ds
        n = read ns
    return (decrypt doc (d,n))

usageMsg :: String
usageMsg = "Enter arguments in the following order \"-encrypt keyfile inputFile outputFile\" or \"-decrypt keyfile inputFile\""

-- reads arguments and calls appropriate function
cmdln :: [String] -> IO String
cmdln ["-gen-keys"] = getKeyPairs
cmdln ["-encrypt", keyFile, inputFile, outputFile] = startEncryption keyFile inputFile outputFile
cmdln ["-decrypt", keyFile, inputFile] = startDecryption keyFile inputFile
cmdln _ = return usageMsg

main :: IO()
main = do
    args <- getArgs
    x <- cmdln args
    putStr x

