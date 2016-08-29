{-
Project: WebMC: a model checker for the web
Author: Victor Ferman
File: OauthServer.hs
Description: This file defines the OAuth Server used for tests etc
-}

module OauthServer where

import qualified Data.Map as Map
import           Server
import           Types

clientServer:: String -> Server
clientServer sName =
    --init sID auto pData kDesc track keys known rules
    initEmptyServer sName ["oauth_nonce", "oauth_timestamp"] ("", []) [] [] []
      kData ruleMap
    where kData = Map.fromList [("oauth_consumer_key", [sName]),
                    ("client_secret",[sName++"secret"]),
                    ("oauth_callback", [show url3]),
                    ("oauth_realm", ["realm"]),
                    ("oauth_signature_method", ["HMAC-SHA1"])]
          url1 = Url sName "one"
          url2 = Url sName "two"
          url3 = Url sName "ready"
          emptyCSP = Csp { scriptList = [], frameList = [], resourceList = []}
          inst1 = Instruction (Left 1) Rule { rType = RuleType Normal Full,
                    rMethod = Post, rUrl = Left url2,
                    rContents = Map.singleton "resource_provider" "?" }
          component1 = Component { cOrigin = url1, cList = [inst1], cPos = 1,
                         cVisible = True}
          response1 = Response {destinationIdentifier = "", origin = url1,
                        resNonce = "", csp = emptyCSP,
                        componentList = [component1],
                        instructionList = PageInstructions { autoList = [],
                          conditionalList = [] }, fileList = Map.empty }
          sRule2 = ServerRule { sReqMethod = Post,
                     sReqUrl =Right "resource_provider",
                     sReqContents = ["oauth_realm","oauth_consumer_key",
                       "oauth_signature_method", "oauth_timestamp",
                       "oauth_nonce", "oauth_callback",
                       "oauth_signature = hash client_secret oauth_realm oauth_consumer_key oauth_signature_method oauth_timestamp oauth_nonce oauth_callback"] }
          inst2 = Instruction (Right True) Rule {rType = RuleType Normal Full,
                     rMethod = Post, rUrl = Right "oauth_authorize",
                     rContents = Map.fromList [("oauth_token", ""), ("oauth_token_secret", ""), ("oauth_callback", "")] }
          response2 = Response {destinationIdentifier = "", origin = url2,
                        resNonce = "", csp = emptyCSP,
                        componentList = [],
                        instructionList = PageInstructions { autoList = [inst2],
                          conditionalList = [] }, fileList = Map.empty }
          sRule3 = ServerRule { sReqMethod = Post,
                     sReqUrl =Right "oauth_token_address",
                     sReqContents = ["oauth_realm", "oauth_consumer_key", "oauth_token", "oauth_signature_method",
                       "oauth_timestamp", "oauth_nonce", "oauth_verifier",
                       "oauth_signature = hash client_secret oauth_realm oauth_consumer_key oauth_token oauth_signature_method oauth_timestamp oauth_nonce oauth_verifier"] }
          inst3 = Instruction (Left 1) Rule { rType = RuleType Normal Full,
                    rMethod = Post, rUrl = Left url3,
                    rContents = Map.singleton "success!!" "?" }
          component3 = Component { cOrigin = url1, cList = [inst3], cPos = 1,
                         cVisible = True}
          response3 = Response {destinationIdentifier = "", origin = url3,
                        resNonce = "", csp = emptyCSP,
                        componentList = [component3],
                        instructionList = PageInstructions { autoList = [],
                          conditionalList = [] }, fileList = Map.empty }
          ruleMap = Map.fromList [(url1, [([], [], response1)]),
                        (url2, [(["resource_provider"], [sRule2], response2)]),
                        (url3, [(["oauth_token", "oauth_verifier", "oauth_token_address"],[sRule3], response3)])]

resourceServer:: String -> Server
resourceServer sName =
    --init sID auto pData kDesc track keys known rules
    initEmptyServer sName [] ("", []) [] [] [] kData ruleMap
    where kData = Map.fromList [("client_identifier", [sName]),
                    ("client_secret",[sName++"secret"]),
                    ("oauth_callback",
                       ["Url {server = \"client\", path = \"ready\"}"]),
                    ("oauth_token_address", [show url5])]
          url1 = Url sName "initiate"
          url2 = Url sName "authorize"
          url3 = Url sName "login"
          url4 = Url sName "confirm"
          url5 = Url sName "token"
          emptyCSP = Csp { scriptList = [], frameList = [], resourceList = []}
          inst1 = Instruction (Left 1) Rule { rType = RuleType Normal Full,
                    rMethod = Post, rUrl = Left url2,
                    rContents = Map.fromList [("oauth_token",""), ("oauth_token_secret", ""), ("oauth_callback_confirmed","")] }
          component1 = Component { cOrigin = url1, cList = [inst1], cPos = 1,
                         cVisible = True}
          response1 = Response {destinationIdentifier = "", origin = url1,
                        resNonce = "", csp = emptyCSP,
                        componentList = [component1],
                        instructionList = PageInstructions { autoList = [],
                          conditionalList = [] }, fileList = Map.empty }
          inst2 = Instruction (Left 1) Rule { rType = RuleType Normal Full,
                    rMethod = Post, rUrl = Left url3,
                    rContents = Map.fromList [("user","?"), ("pass", "?"), ("oauth_token", ""), ("oauth_callback", ""), ("oauth_token_secret", "")] }
          component2 = Component { cOrigin = url2, cList = [inst2], cPos = 1,
                         cVisible = True}
          response2 = Response {destinationIdentifier = "", origin = url2,
                        resNonce = "", csp = emptyCSP,
                        componentList = [component2],
                        instructionList = PageInstructions { autoList = [],
                          conditionalList = [] }, fileList = Map.empty }
          inst3 = Instruction (Left 1) Rule { rType = RuleType Normal Full,
                    rMethod = Post, rUrl = Left url4,
                    rContents = Map.fromList [("oauth_token", ""), ("oauth_callback", ""), ("oauth_token_secret", "")] }
          component3 = Component { cOrigin = url3, cList = [inst3], cPos = 1,
                         cVisible = True}
          response3 = Response {destinationIdentifier = "", origin = url3,
                        resNonce = "", csp = emptyCSP,
                        componentList = [component3],
                        instructionList = PageInstructions { autoList = [],
                          conditionalList = [] }, fileList = Map.empty }
          inst4 = Instruction (Left 1) Rule { rType = RuleType Normal Full,
                    rMethod = Post, rUrl = Right "oauth_callback",
                    rContents = Map.fromList [("oauth_token", ""), ("oauth_verifier", ""), ("oauth_token_address", "")] }
          response4 = Response {destinationIdentifier = "", origin = url4,
                        resNonce = "", csp = emptyCSP,
                        componentList = [],
                        instructionList = PageInstructions { autoList = [inst4],
                          conditionalList = [] }, fileList = Map.empty }
          ruleMap = Map.fromList [(url1, [(["oauth_realm","oauth_consumer_key",
                                              "oauth_signature_method",
                                              "oauth_timestamp",
                                              "oauth_nonce", "oauth_callback",
                                              "oauth_signature"], [],
                                              response1)]),
                        (url2, [(["oauth_token", "oauth_callback", "oauth_token_secret"], [], response2)]),
                        (url3, [(["user", "pass", "oauth_token", "oauth_callback", "oauth_verifier"],[], response3)]),
                        (url4, [(["oauth_token", "oauth_verifier", "oauth_callback"],[], response4)]),
                        (url5, [(["oauth_realm", "oauth_consumer_key", "oauth_token", "oauth_signature_method",
                          "oauth_timestamp", "oauth_nonce", "oauth_verifier"],
                          [], response4)])]


getServers :: ([Server], Request)
getServers = ([resource, client], req)
    where client= clientServer "client"
          resource = resourceServer "resource"
          req = Request "" (Url "" "") "" Post Map.empty
