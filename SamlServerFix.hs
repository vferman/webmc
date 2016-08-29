{-
Project: WebMC: a model checker for the web
Author: Victor Ferman
File: SamlServer.hs
Description: This file defines the SAML Server used for tests etc
-}

module SamlServerFix where

import qualified Data.Map as Map
import           Server
import           Attacker
import           Types

rpServer :: String -> Server
rpServer sName =
    initEmptyServer sName [] ("", []) [] [] [] kData ruleMap
    where url1 = Url sName "one"
          url2 = Url sName "two"
          url3 = Url sName "three"
          kData = Map.fromList [("rp", [sName])]
          emptyCSP = Csp { scriptList = [], frameList = [], resourceList = []}
          inst1 = Instruction (Left 1) Rule { rType = RuleType Normal Full,
                    rMethod = Post, rUrl = Left url2,
                    rContents = Map.fromList [("id", "?"), ("idp", "?")] }
          component1 = Component { cOrigin = url1, cList = [inst1], cPos = 1,
                         cVisible = True}
          response1 = Response {destinationIdentifier = "", origin = url1,
                        resNonce = "", csp = emptyCSP,
                        componentList = [component1],
                        instructionList = PageInstructions { autoList = [],
                          conditionalList = [] }, fileList = Map.empty }
          inst2 = Instruction (Right True) Rule {rType = RuleType Normal Full,
                    rMethod = Post, rUrl = Right "idp",
                    rContents = Map.fromList [("id",""), ("idp", ""),
                      ("return", show url3)] }
          response2 = Response { destinationIdentifier = "", origin= url2,
                        resNonce ="", csp = emptyCSP, componentList = [],
                        instructionList = PageInstructions { autoList = [inst2],
                          conditionalList = [] }, fileList = Map.empty}
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
          ruleMap = Map.fromList [(url1, [([], [], response1, Nothing)]),
                      (url2, [(["id", "idp"], [], response2, Nothing)]),
                      (url3, [(["id", "idp", "authAssert"], [], response3, Nothing)])]


idpServer :: String -> Server
idpServer sName =
    initEmptyServer sName [] ("", []) [] [] [] kData ruleMap
    where url1 = Url sName "one"
          url2 = Url sName "two"
          kData = Map.fromList [("id", ["userid"]), ("user", ["uname"]),
                ("pass", ["pass"]), ("idp",[show url1])]
          emptyCSP = Csp { scriptList = [], frameList = [], resourceList = []}
          inst1 = Instruction (Left 1) Rule { rType = RuleType Normal Full,
                    rMethod = Post, rUrl = Left url2,
                    rContents = Map.fromList [("user", "?"), ("pass", "?"), ("return", ""), ("id", ""), ("idp", "")] }
          component1 = Component { cOrigin = url1, cList = [inst1], cPos = 1,
                         cVisible = True}
          response1 = Response {destinationIdentifier = "", origin = url1,
                        resNonce = "", csp = emptyCSP,
                        componentList = [component1],
                        instructionList = PageInstructions { autoList = [],
                          conditionalList = [] }, fileList = Map.empty }
          inst2 = Instruction (Right True) Rule {rType = RuleType Normal Full,
                    rMethod = Post, rUrl = Right "return",
                    rContents = Map.fromList [("rp", ""), ("id", ""),
                      ("idp", ""), ("authAssert","Sig rp idp Pri \"idp\"")] }
          response2 = Response { destinationIdentifier = "", origin= url2,
                        resNonce ="", csp = emptyCSP, componentList = [],
                        instructionList = PageInstructions { autoList = [inst2],
                          conditionalList = [] }, fileList = Map.empty}
          ruleMap = Map.fromList
                      [(url1, [ (["id", "rp", "return", "idp"], [],
                        response1, Nothing)]),
                      (url2, [(["user", "pass", "id", "rp", "return", "idp"],
                        [], response2, Nothing)])]

getServers :: ([Server], [Either Request Response], Attacker)
getServers = ([idpS, rpS, rp2S], req, myAttacker)
    where idpS= idpServer "idp"
          rpS = rpServer "rp"
          rp2S = rpServer "rp2"
          pKey = privateKey idpS
          idpUrl = Url "idp" "one"
          knowledge = Map.fromList [("rp", "rp2"),
            ("authAssert", "Sig rp rp2 idp "++ show idpUrl ++ " "++ show pKey)]
          req = [Left (Request "attacker" (Url "rp2" "three") "" Post knowledge)]
          aKnown = Map.fromList [("rp", "rp2")]
          myAttacker = initAttacker "attacker" False ["rp"] []
                        [idpS, rpS, rp2S] [] Map.empty aKnown
