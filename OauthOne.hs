{-
Project: WebMC: a model checker for the web
Author: Victor Ferman
File: OauthOne.hs
Description: This file defines the oauth 1.0 protocol used for tests etc
-}

module OauthOne where

import qualified Data.Map as Map
import           Server
import           Attacker
import           Types
emptyCSP :: Csp
emptyCSP = Csp { scriptList = [], frameList = [], resourceList = []}

clientServer:: String -> String -> Server
clientServer cName sName =
    initEmptyServer cName auto ("", []) [] [] [shrK] kData ruleMap
    --init sID auto pData kDesc track keys known rules
    where shrK = Shr sName cName
          auto = ["oauth_timestamp", "oauth_nonce"]
          urlCB = Url cName "ready"
          url1 = Url cName "one"
          url2 = Url cName "two"
          signature = Sig cName shrK
          kData = Map.fromList [("oauth_consumer_key", [cName]),
                    ("clientSecret", [show shrK]), ("oauth_realm", ["service"]),
                    ("oauth_signature_method", ["HMAC-SHA1"]),
                    ("oauth_callback", [show urlCB]),
                    ("oauth_signature", [show signature])]
          inst1 = Instruction (Left 1) Rule { rType = RuleType Normal Full,
                    rMethod = Post, rUrl = Left url2,
                    rContents = Map.singleton "resource_url" "?" }
          component1 = Component { cOrigin = url1, cList = [inst1], cPos = 1,
                         cVisible = True}
          response1 = Response {destinationIdentifier = "", origin = url1,
                        resNonce = "", csp = emptyCSP,
                        componentList = [component1],
                        instructionList = PageInstructions { autoList = [],
                          conditionalList = [] }, fileList = Map.empty }
          srule2 = ServerRule {sReqMethod = Get, sReqUrl = Right "resource_url",
                     sReqContents = ["oauth_realm", "oauth_consumer_key",
                       "oauth_signature_method", "oauth_timestamp",
                       "oauth_nonce", "oauth_callback", "oauth_signature"]}
          inst2 = Instruction (Right True) Rule { rType = RuleType Normal Full,
                    rMethod = Post, rUrl = Right "auth_url",
                    rContents = Map.fromList [("oauth_callback", ""), ("oauth_token", ""), ("oauth_token_secret", "")] }
          response2 = Response {destinationIdentifier = "", origin = url1,
                        resNonce = "", csp = emptyCSP, componentList = [],
                        instructionList = PageInstructions { autoList = [inst2],
                        conditionalList = [] }, fileList = Map.empty }
          srule3 = ServerRule {sReqMethod = Get, sReqUrl = Right "token_url",
                     sReqContents = ["oauth_consumer_key", "oauth_token",
                       "oauth_signature_method", "oauth_timestamp",
                       "oauth_nonce", "oauth_verifier", "oauth_signature"]}
          inst3 = Instruction (Left 1) Rule { rType = RuleType Normal Full,
                    rMethod = Post, rUrl = Left urlCB,
                    rContents = Map.singleton "Success!!!" "?" }
          component3 = Component { cOrigin = urlCB, cList = [inst3], cPos = 1,
                         cVisible = True}
          response3 = Response {destinationIdentifier = "", origin = urlCB,
                        resNonce = "", csp = emptyCSP,
                        componentList = [component3],
                        instructionList = PageInstructions { autoList = [],
                          conditionalList = [] }, fileList = Map.empty }
          ruleMap = Map.fromList [
                      (url1, [([], [], response1, Nothing)]),
                      (url2, [(["resource_url"], [srule2], response2, Nothing)]),
                      (urlCB, [(["oauth_token", "oauth_token_secret",
                        "oauth_verifier","token_url"], [srule3], response3, Nothing)]) ]

resourceServer::String -> [String] -> Server
resourceServer sName cNames =
    initEmptyServer sName auto ("", []) [] sList shrKeys kData ruleMap
    where shrKeys = map (Shr sName) cNames
          shrSec = map show shrKeys
          sList = ["oauth_verifier", "oauth_token", "oauth_timestamp",
                    "oauth_nonce"]
          cbUrls = map (\c -> show (Url c "ready") ) cNames
          auto = ["oauth_token","oauth_token_secret","oauth_verifier"]
          kData = Map.fromList [("oauth_consumer_key", cNames),
                    ("oauth_client_secret", shrSec), ("oauth_callback", cbUrls)]
          url1 = Url sName "initiate"
          url2 = Url sName "authorize"
          url3 = Url sName "three"
          url4 = Url sName "token"
          inst1 = Instruction (Right True)
                    Rule { rType = RuleType Normal Full, rMethod = Post,
                      rUrl = Right "",
                      rContents = Map.fromList [("oauth_token", ""),
                        ("oauth_token_secret", ""),
                        ("oauth_callback_confirmed","true"),
                        ("auth_url", show url2)]}
          response1 = Response {destinationIdentifier = "", origin = url1,
                        resNonce = "", csp = emptyCSP,
                        componentList = [],
                        instructionList = PageInstructions { autoList = [inst1],
                        conditionalList = [] }, fileList = Map.empty }
          inst2 = Instruction (Left 1) Rule { rType = RuleType Normal Full,
                    rMethod = Post, rUrl = Left url3,
                    rContents = Map.fromList [("user", "?"), ("pass", "?"),
                                  ("oauth_callback", ""), ("oauth_token", ""),
                                  ("oauth_token_secret", "")] }
          component2 = Component { cOrigin = url2, cList = [inst2], cPos = 1,
                         cVisible = True}
          response2 = Response {destinationIdentifier = "", origin = url2,
                        resNonce = "", csp = emptyCSP,
                        componentList = [component2],
                        instructionList = PageInstructions { autoList = [],
                                            conditionalList = [] },
                        fileList = Map.empty }
          inst3 = Instruction (Right True) Rule { rType = RuleType Normal Full,
                    rMethod = Post, rUrl = Right "oauth_callback",
                    rContents = Map.fromList [("oauth_token", ""), ("oauth_token_secret", ""), ("oauth_verifier", ""), ("token_url", show url4)] }
          response3 = Response {destinationIdentifier = "", origin = url3,
                        resNonce = "", csp = emptyCSP, componentList = [],
                        instructionList = PageInstructions { autoList = [inst3],
                        conditionalList = [] }, fileList = Map.empty }
          inst4 = Instruction (Right True)
                    Rule { rType = RuleType Normal Full, rMethod = Post,
                    rUrl = Right "",
                    rContents = Map.fromList [("oauth_token", ""),
                    ("oauth_token_secret", "")]}
          response4 = Response {destinationIdentifier = "", origin = url4,
                        resNonce = "", csp = emptyCSP,
                        componentList = [],
                        instructionList = PageInstructions { autoList = [inst4],
                        conditionalList = [] }, fileList = Map.empty }
          ruleMap = Map.fromList [
                      (url1, [(["oauth_realm", "oauth_consumer_key",
                        "oauth_signature_method", "oauth_timestamp",
                        "oauth_nonce", "oauth_callback", "oauth_signature"], [],
                        response1, Nothing)]),
                      (url2, [(["oauth_callback", "oauth_token",
                        "oauth_token_secret"], [], response2, Nothing)]),
                      (url3, [(["user", "pass", "oauth_callback", "oauth_token",
                          "oauth_token_secret"], [], response3, Nothing)]),
                      (url4, [(["oauth_consumer_key", "oauth_token",
                        "oauth_signature_method", "oauth_timestamp",
                        "oauth_nonce", "oauth_verifier", "oauth_signature"], [],
                        response4, Nothing)]) ]

getServers :: ([Server], [Either Request Response], Attacker)
getServers = ([clientS, resS], rList, myAttacker)
    where clientS= clientServer "client" "resource"
          resS = resourceServer "resource" ["client"]
          cbUrl = Url "client" "ready"
          shrK = Shr "resource" "client"
          signature = Sig "client" shrK
        --StepOne
        --   dUrl = Url "client" "one"
        --   req = Request { originIdentifier = "browser", destination = dUrl,
        --           reqNonce = "", method = Get, payload = Map.empty }
        --StepTwo
        --   dUrl = Url "client" "two"
        --   resUrl = Url "resource" "initiate"
        --   rKnown = Map.singleton "resource_url" (show resUrl)
        --   req = Request { originIdentifier = "browser", destination = dUrl,
        --              reqNonce = "", method = Post, payload = rKnown }
        --FinalStep
        --   inst3 = Instruction (Left 1) Rule { rType = RuleType Normal Full,
        --           rMethod = Post, rUrl = Left cbUrl,
        --           rContents = Map.singleton "Success!!!" "?" }
        --   component3 = Component { cOrigin = cbUrl, cList = [inst3], cPos = 1,
        --                cVisible = True}
        --   response3 = Response {destinationIdentifier = "browser",
        --               origin = cbUrl, resNonce = "", csp = emptyCSP,
        --               componentList = [component3],
        --               instructionList = PageInstructions { autoList = [],
        --                 conditionalList = [] }, fileList = Map.empty }
        --   rList = [Right response3]
          --attack
          resUrl = Url "resource" "token"
          rKnown = Map.fromList [("oauth_consumer_key", "client"),
                      ("oauth_token", ""), --("user", ""),
                      ("oauth_signature_method", "HMAC-SHA1"),
                      ("oauth_timestamp", ""), ("oauth_nonce", ""),
                      ("oauth_verifier", ""),
                      ("oauth_signature", show signature)]
          req = Request { originIdentifier = "attacker", destination = resUrl,
                  reqNonce = "", method = Post, payload = rKnown }
          rList = [Left req]
          aKnown = Map.fromList [("oauth_consumer_key", "client"),
                     ("clientSecret", show shrK), ("oauth_realm", "service"),
                     ("oauth_signature_method", "HMAC-SHA1"),
                     ("oauth_callback", show cbUrl),
                     ("oauth_signature", show signature)]
          myAttacker = initAttacker "attacker" True ["client"] []
                        [clientS, resS] ["oauth_timestamp",  "oauth_nonce",
                          "oauth_verifier"] Map.empty aKnown
