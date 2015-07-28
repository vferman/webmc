{-
Project: WebMC: a model checker for the web
Author: Victor Ferman
File: User.hs
Description: This file defines user's actions an capabilities, used in order to
    access the user knowledge and to define what are the possible actions the
    user can take at any ginven moment.

-}

module User
( module User
, module Types
)where

import Types
--import Messages
import Data.Char
import qualified Data.Map as Map

{-
    Function used to calculate what are the possible actions of a user.
    it takes Maybe Display to account for the first steps, in case of having an
    actual display it will analyze it and will return a list links, buttons and
    forms.

-}
actions:: Display -> [String]
actions display
    | bVal && fVal= ["url","null","back","forward"] ++ otherActions
    | bVal = ["url","null","back"] ++ otherActions
    | fVal = ["url","null","forward"] ++ otherActions
    | otherwise = ["url", "null"] ++ otherActions
    where (Display { lock = _, location = _, visibleLinks = visible,
             visibleForms = vForms, back = bVal, forward = fVal}) = display
          formActions = if not (Map.null vForms)
                          then map (\ (k,v) -> show k ++ " "
                            ++ concatMap (++ " ") v) $ Map.toList vForms
                          else []
          linkActions = if not (null visible) then map show visible else []
          otherActions = linkActions ++ formActions

--Auxiliar function to access specific user data
getIdentifierData:: (k -> v -> Bool) -> [Map.Map k v] -> Map.Map k v
getIdentifierData _ [] = Map.empty
getIdentifierData f (x:_) = Map.filterWithKey f x

-- Auxiliar function to get data from the user, in case its needed for an
-- event and it exists in its knowledge base
getUserKnowledge:: User -> [Domain] -> [String] -> Known
getUserKnowledge iUser domainList identifiers =
    getIdentifierData (\k _ -> elem k identifiers) $ Map.elems matchingDomains
    where (User {userIdentifier = _, userKnowledge = uKnown,
            knownUrls = _}) = iUser
          matchingDomains = Map.filterWithKey (\k _ -> elem k domainList) uKnown

-- Function to go from an string to an actual input
optionToEvent:: String -> User -> Maybe Url -> Maybe UserInput
optionToEvent option iUser (Just url)
    | act=="url" = Just (Address url)
    | all isDigit act && not (null params) = Just (Form (FormInput
                                               (getUserKnowledge iUser [domain]
                                               params) (stringToPos act)))
    | otherwise=Nothing
    where (act:params)=words option
          (Url {server = domain, path = _ }) = url
optionToEvent option _ Nothing
    | act=="null" = Just Null
    | act=="back" = Just Back
    | act=="forward" = Just Forward
    | all isDigit act && null params= Just (Position $ stringToPos act)
    | otherwise=Nothing
    where (act:params)=words option
