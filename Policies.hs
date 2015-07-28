{-
Project: WebMC: a model checker for the web
Author: Victor Ferman
File: Policies.hs
Description: This file defines tyhe security policies for the browser, is a
    different module so that people and researchers can easily modify the
    policies and research how different policies may affect the security of the
    system
-}

module Policies where

import Types

{-
    Same origin policy, basically useful when receiving a response, sincel the
    requests will always be made due to the attacker having control over the
    network and thus can flush all of the preflight requests
-}
sameOriginPolicy:: Url -> Rule -> Bool
sameOriginPolicy rOrigin rule
    |reqType == Normal && (cType == Full || cType == Frame) = True
    |originServer == destinationServer = True
    |otherwise = False
    where (Rule {rType = RuleType reqType cType, rMethod = _,
            rUrl = Url {server = destinationServer, path = _ },
            rContents = _ }) = rule
          (Url {server = originServer, path = _}) = rOrigin


{-
    Content Security Policy, checks wether an instruction url is within the
    whitelist corresponding to the kind of request, however unlike other
    withelist approaches (in order to mantain backwards compatibility) an
    empty list means that any domain is allowed
-}

contentSecurityPolicy:: Csp -> Rule -> Bool
contentSecurityPolicy policies rule =
    cType == Full ||
      cType == Script && null sList ||
      cType == Frame && null fList &&
        (iRType == Normal || elem "javascript://" sList || null sList) ||
      cType == Resource && null rList &&
        (iRType == Normal || elem "javascript://" sList || null sList) ||
      cType == Script &&  elem destinationServer sList &&
        ((iRType == Scripted && elem "javascript://" sList) ||
            iRType == Normal) ||
      cType == Frame && elem destinationServer fList &&
        ((iRType == Scripted && (elem "javascript://" sList || null sList)) ||
          iRType == Normal) ||
      cType == Resource && elem destinationServer rList &&
        ((iRType == Scripted && (elem "javascript://" sList || null sList)) ||
            iRType == Normal)
    where ( Rule {rType = RuleType iRType cType, rMethod = _,
             rUrl = Url { server = destinationServer, path = _ },
             rContents = _ }) = rule
          (Csp {scriptList = sList, frameList = fList, resourceList = rList}) = policies
