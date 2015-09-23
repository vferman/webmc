module Encryption
where

import Types

inv:: Key -> Key
inv (Pub str) = Pri str
inv (Pri str) = Pub str
inv (Shr strA strB) = Shr strA strB

encrypt:: String -> Key -> Enc String
encrypt str eKey@(Pri _) = Sig str eKey
encrypt str eKey= Enc str eKey

getEncVal:: Enc a -> (a, Key)
getEncVal (Enc val key) = (val, key)
getEncVal (Sig val key) = (val, key)

decrypt :: Enc a -> Key -> Maybe a
decrypt enc dKey
    | inv eKey == dKey = Just val
    | otherwise = Nothing
    where (val, eKey) = getEncVal enc

verify :: Enc a -> Key -> Maybe a
verify val@(Sig _ _) key = decrypt val key
verify (Enc _ _) _ = Nothing
