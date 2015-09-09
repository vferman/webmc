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

import           Data.Char
import qualified Data.Map  as Map
import           Types
import Debug.Trace


{-
    Function used to calculate what are the possible actions of a user.
    it takes Maybe Display to account for the first steps, in case of having an
    actual display it will analyze it and will return a list links, buttons and
    forms.

-}
actions:: User -> Display -> [String]
actions cUser display
    | bVal && fVal= ["U -> B: back","U -> B: forward"] ++ urlInput ++ otherActions
    | bVal = ["U -> B: back"] ++ urlInput ++ otherActions
    | fVal = ["U -> B: forward"] ++ urlInput ++ otherActions
    | otherwise = urlInput ++ otherActions
    where (Display { lock = _, location = _, visibleLinks = visible,
             visibleForms = vForms, back = bVal, forward = fVal}) = display
          formActions = if not (Map.null vForms)
                          then map (\(k, v) -> "U -> B: " ++ show k ++ " "
                            ++ unwords v) $ Map.toList vForms
                          else []
          linkActions = if not (null visible)
                            then map (\e -> "U -> B: Click" ++ show e) visible
                            else []
          otherActions = linkActions ++ formActions
          urlInput = map (\url -> "U -> B: "++ show url) (knownUrls cUser)


-- Auxiliar function to get data from the user, in case its needed for an
-- event and it exists in its knowledge base
getUserKnowledge:: User -> [Domain] -> [String] -> Known
getUserKnowledge iUser domainList identifiers =
    Map.filterWithKey (\k _ -> elem k identifiers) $
      Map.unions (gKnown : Map.elems matchingDomains)
    where (User {generalKnowledge = gKnown, domainKnowledge = dKnown }) = iUser
          matchingDomains = Map.filterWithKey (\k _ -> elem k domainList) dKnown

-- Function to go from an string to an actual input
optionToEvent:: String -> User -> Maybe UserInput
optionToEvent option iUser
    | act=="Url" = Just (Address (read $ unwords (act:params)))
    | all isDigit act && null params= Just (Position $ stringToPos act)
    | all isDigit act && not (null params) =
          let (sUrl, query)= break (=='}') (unwords params)
          in Just (Form (FormInput (getUserKnowledge iUser
            [server (read (sUrl++"}"))] (words (drop 2 query)))
            (stringToPos act)))
    | act=="back" = Just Back
    | act=="forward" = Just Forward
    | otherwise = Nothing
    where (act:params)=words $ drop 8 option
