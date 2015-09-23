{-
Project: WebMC: a model checker for the web
Author: Victor Ferman
File: Attacker.hs
Description: This file defines a generic Attacker's actions an capabilities,
    used in order to know what the attacker needs in order to achieve a
    successful attack on a protocol
-}

module Attacker where

import qualified Data.Map as Map
import           Types

initAttacker :: String -> [String] -> Request -> [String] -> Known -> Attacker
initAttacker aID corruptSID aGoal autoGen aKnown =
    Attacker { attackerIdentifier = aID, acquiredKeys = [],
                serverIDs = corruptSID, goal = aGoal, generated = autoGen,
                acquiredInfo = Map.empty, attackerKnowledge = aKnown,
                aNonceList = [1..] }

getInfoFromServer :: Attacker -> Server -> Attacker
getInfoFromServer attackr servr
    | serverIdentifier servr `elem` corruptSID =
          Attacker { attackerIdentifier = aID, acquiredKeys = kList,
            serverIDs = corruptSID, goal = aGoal, generated = autoGen,
            acquiredInfo = Map.union browserInfo aInfo,
            attackerKnowledge = aKnown, aNonceList = aNL }
    | otherwise = attackr
    where (Attacker { attackerIdentifier = aID, serverIDs = corruptSID,
            goal = aGoal, generated = autoGen, acquiredInfo = aInfo,
            attackerKnowledge = aKnown, aNonceList = aNL }) = attackr
          sessions = serverSession servr
          kList = privateKey servr:knownKeys servr
          browserInfo = Map.foldWithKey
            (\_ value accum -> Map.unions
               [maybe Map.empty (`Map.singleton` value)
                  (Map.lookup "dID" value), accum]) Map.empty sessions

getInfoFromServerList :: Attacker -> [Server] -> Attacker
getInfoFromServerList = foldl getInfoFromServer


incompleteData :: [String] -> [String] -> [String] -> Maybe Known -> [String]
incompleteData needed _ _ Nothing =  needed
incompleteData needed auto known (Just info) = results
    where iKeys = Map.keys info
          notInAuto = filter (`notElem` auto) needed
          notInKnown = filter (`notElem` known) notInAuto
          results = filter (`notElem` iKeys) notInKnown

neededInfo :: Attacker -> [[String]]
neededInfo attackr = results
    where (Attacker { goal = aGoal, generated = autoGen, acquiredInfo = info,
            attackerKnowledge = aKnown })= attackr
          goalData = payload aGoal
          neededData = Map.keys goalData
          browsers = Map.keys info
          results = map (\brwsr -> brwsr:
                      incompleteData neededData autoGen (Map.keys aKnown)
                      (Map.lookup brwsr info) ) browsers
