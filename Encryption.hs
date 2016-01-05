module Encryption
where

import Types
import qualified Data.Map as Map

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

hash :: String -> Known -> Maybe String
hash cStr known
    | not (null wList) && head wList == "hash" =
        let filt = Map.filterWithKey (\k _ -> k `elem` drop 1 wList) known
            res = Map.foldlWithKey (\acc key val -> acc ++ key ++ " " ++ val ++
                                        " " ) "" filt
        in if length (Map.keys filt) == length (drop 1 wList)
             then Nothing
             else Just res
    | otherwise = Nothing
    where wList = words cStr
