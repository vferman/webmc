{-
Project: WebMC: a model checker for the web
Author: Victor Ferman
File: WebKereberos.hs
Description: This file defines the Kereberos protocol for the web, used for
tests etc
-}

module WebKereberos where

import qualified Data.Map as Map
import           Server
import           Attacker
import           Types
emptyCSP :: Csp
emptyCSP = Csp { scriptList = [], frameList = [], resourceList = []}

webAS:: String -> String -> Server
webAS cName kdc =
    initEmptyServer cName [] ("", []) [] [] [pkey] Map.empty ruleMap
    --init sID auto pData kDesc track keys known rules
    where kdcUrl = Url kdc "one"
          pkey = Pub kdc
          url1 = Url cName "one"
          cbUrl = Url cName "two"
          inst1 = Instruction (Right True) Rule { rType = RuleType Normal Full,
                    rMethod = Post, rUrl = Left kdcUrl,
                    rContents = Map.singleton "cbUrl" (show cbUrl) }
          response1 = Response {destinationIdentifier = "", origin = url1,
                      resNonce = "", csp = emptyCSP, componentList = [],
                      instructionList = PageInstructions { autoList = [inst1],
                                          conditionalList = [] },
                      fileList = Map.empty}
          inst2 = Instruction (Left 1) Rule { rType = RuleType Normal Full,
                                rMethod = Post, rUrl = Left url1,
                                rContents = Map.singleton "success!!" "?" }
          component2 = Component { cOrigin = url1, cList = [inst2], cPos = 1,
                                     cVisible = True}
          response2 = Response {destinationIdentifier = "", origin = url1,
                        resNonce = "", csp = emptyCSP,
                        componentList = [component2],
                        instructionList = PageInstructions { autoList = [],
                                            conditionalList = [] },
                        fileList = Map.empty }
          inst3 = Instruction (Left 1) Rule { rType = RuleType Normal Full,
                                rMethod = Post, rUrl = Left cbUrl,
                                rContents = Map.singleton "success!!" "?" }
          component3 = component2 {cOrigin = cbUrl, cList = [inst3]}
          response3 =  response2 {origin = cbUrl, componentList = [component3] }

          ruleMap = Map.fromList [
                      (url1, [(["id_token"], [], response2, Just response1),
                              ([], [], response1, Nothing)]),
                      (cbUrl, [(["id_token"], [], response3, Nothing) ]) ]

webKDC:: String -> Server
webKDC cName =
    initEmptyServer cName auto pdata [] [] [] known ruleMap
    --init sID auto pData kDesc track keys known rules
    where auto = ["credentials"]
          pdata = ("id_token", ["cbUrl"])
          known = Map.fromList [("user", ["uname"]), ("pass", ["pass"])]
          url1 = Url cName "one"
          url2 = Url cName "two"
          pKey = Pri cName
          inst1 = Instruction (Left 1) Rule { rType = RuleType Normal Full,
                    rMethod = Post, rUrl = Left url2,
                    rContents = Map.fromList [("user", "?"), ("pass", "?"), ("cbUrl", "")] }
          component1 = Component { cOrigin = url1, cList = [inst1], cPos = 1,
                       cVisible = True}
          response11 = Response {destinationIdentifier = "", origin = url1,
                      resNonce = "", csp = emptyCSP,
                      componentList = [component1],
                      instructionList = PageInstructions { autoList = [],
                                          conditionalList = [] },
                      fileList = Map.empty }
          inst2 = Instruction (Right True) Rule { rType = RuleType Normal Full,
                    rMethod = Post, rUrl = Right "cbUrl",
                    rContents = Map.empty }
          f1 = WebFile 3600 $ Map.singleton "credentials" ""
          f2 = WebFile 3600 $ Map.singleton "id_token" ("Sig credentials "++ show pKey)
          fm = Map.fromList [(Left "cbUrl", f2), (Right (Url cName ""), f1)]
          response2 = Response {destinationIdentifier = "", origin = url2,
                      resNonce = "", csp = emptyCSP, componentList = [],
                      instructionList = PageInstructions { autoList = [inst2],
                                          conditionalList = [] },
                      fileList = fm }
          ruleMap = Map.fromList [
                (url1, [(["cbUrl"], [], response11, Nothing),
                        (["credentials", "cbUrl"], [], response2,
                          Just response11),
                        (["crendentials", "reauth", "cbUrl"], [], response11,
                          Nothing)]),
                (url2, [(["user", "pass", "cbUrl"], [], response2, Nothing)])]

aServer::String -> Server
aServer cName = initEmptyServer cName ["id_token"] ("",[]) [] [] [] Map.empty ruleMap
    where url1 = Url cName ""
          response1 = Response {destinationIdentifier = "", origin = url1,
                  resNonce = "", csp = emptyCSP,
                  componentList = [],
                  instructionList = PageInstructions { autoList = [],
                                      conditionalList = [] },
                  fileList = Map.empty }
          ruleMap = Map.fromList [ (url1, [([], [], response1,
                                     Just response1)])]

getServers :: ([Server], [Either Request Response], Attacker)
getServers = ([kdc, was, aServ], goals, myAttacker)
    where kdc = webKDC "kdc"
          was = webAS "was" "kdc"
          aServ = aServer "att"
          --url1 = Url { server = "was", path = "one" }
          cbUrl = Url { server = "was", path = "two" }
          --aUrl = Url { server = "att", path = "" }
          aKnown = Map.fromList [("user", "uname"), ("pass", "pass"),
                     ("cbUrl", show cbUrl) ]
          rPayload1 = Map.fromList [("id_token", "")]
          req1 = Request { originIdentifier = "attacker", destination = cbUrl,
                   reqNonce = "", method = Post, payload = rPayload1 }
        --   req2 = Request {originIdentifier = "browser", destination = aUrl,
        --      reqNonce = "", method = Get, payload = Map.empty }
        --   rPayload3= Map.fromList [("id_token", "")]
        --   req3 = Request {originIdentifier = "browser", destination = url1,
        --            reqNonce = "", method = Post, payload = rPayload3 }
          goals = [Left req1]--, Left req2, Left req3]
          myAttacker = initAttacker "attacker" True ["att"] []
                        [kdc, was, aServ] [] Map.empty aKnown

secondGoal::State -> State
secondGoal cState = nState
    where cUser = user cState
          cAttacker = attacker cState
          cGoals = mGoals cState
          url1 = Url { server = "was", path = "one" }
          aUrl = Url { server = "att", path = "" }
          kUrls = [aUrl]
          req2 = Request {originIdentifier = "browser", destination = aUrl,
             reqNonce = "", method = Get, payload = Map.empty }
          rPayload = Map.fromList [("id_token", "")]
          req3 = Request {originIdentifier = "browser", destination = url1,
                   reqNonce = "", method = Post, payload = rPayload }
          nUser = cUser {knownUrls = kUrls}
          nAttacker = cAttacker { asSessions = False }
          nGoals = Left req2:Left req3:cGoals
          nState = cState {user = nUser, attacker= nAttacker, mGoals = nGoals}
          --url1 = Url { server = "was", path = "one" }
          --url2 = Url { server = "kdc", path = "two" }
          --   inst1 = Instruction (Left 1) Rule { rType = RuleType Normal Full,
          --             rMethod = Post, rUrl = Left cbUrl,
          --             rContents = Map.singleton "success!!" "?" }
          --   component1 = Component { cOrigin = cbUrl, cList = [inst1], cPos = 1,
          --                               cVisible = True}
          --   res1 = Response { destinationIdentifier = "attacker",
          --                 origin = cbUrl, resNonce = "", csp = emptyCSP,
          --                 componentList = [component1],
          --                 instructionList = PageInstructions { autoList = [],
          --                                     conditionalList = [] },
          --                 fileList = Map.empty }
