{-
Project: WebMC: a model checker for the web
Author: Victor Ferman
File: OIDServer.hs
Description: This file defines the OpenID Server used for tests etc
-}

module OIDServer where

import qualified Data.Map as Map
import           Server
import           Attacker
import           Types

oid::Url
oid = Url { server = "specs.openid.net", path ="/auth/2.0" }

rpServer:: String -> Server
rpServer sName =
    --init sID auto pData kDesc track keys known rules
    initEmptyServer sName auto ("", []) ["openid.mac_key"] ["openid.response_nonce"] [] kData
      ruleMap
    where url1 = Url { server = sName, path = "one" }
          url2 = Url { server = sName, path = "two" }
          url3 = Url { server = "op", path = "four" }
          url4 = Url { server = sName, path = "three" }
          url5 = Url { server = sName, path = "four" }
          auto = ["openid.dh_modulus", "openid.dh_gen",
            "openid.dh_consumer_public", "session"]
          kData = Map.fromList [("rp", [sName]), ("openid.ns", [show oid]),
            ("opened.mode", ["associate"]), ("openid.assoc_type", ["HMAC-SHA256"]),
            ("openid.session_type", ["stype"])]
          emptyCSP = Csp { scriptList = [], frameList = [], resourceList = []}
          inst1 = Instruction (Left 1) Rule { rType = RuleType Normal Full,
                    rMethod = Post, rUrl = Left url2,
                    rContents = Map.singleton "openid_identity" "?" }
          component1 = Component { cOrigin = url1, cList = [inst1], cPos = 1,
                         cVisible = True}
          response1 = Response {destinationIdentifier = "", origin = url1,
                        resNonce = "", csp = emptyCSP,
                        componentList = [component1],
                        instructionList = PageInstructions { autoList = [],
                          conditionalList = [] }, fileList = Map.empty }
          srule2 = ServerRule { sReqMethod = Get,
                     sReqUrl =Right "openid_identity",
                     sReqContents = ["openid_identity"] }
          inst2 = Instruction (Left 1) Rule { rType = RuleType Normal Full,
                    rMethod = Post, rUrl = Left url3,
                    rContents = Map.fromList [("openid.ns", ""),
                      ("openid.mode", ""), ("openid.claimed_id", ""),
                      ("openid.identity", ""), ("openid.assoc_handle", ""),
                      ("openid.return_to", show url4), ("openid.realm", "")]}
          component2 = Component { cOrigin = url2, cList = [inst2], cPos = 1,
                         cVisible = True}
          response2 = Response {destinationIdentifier = "", origin = url2,
                        resNonce = "", csp = emptyCSP,
                        componentList = [component2],
                        instructionList = PageInstructions { autoList = [],
                          conditionalList = [] }, fileList = Map.empty }
          inst3 = Instruction (Right True) Rule { rType = RuleType Normal Full,
                    rMethod = Get, rUrl = Left url5, rContents= Map.empty}
          response3 = Response {destinationIdentifier = "", origin = url4,
                        resNonce = "", csp = emptyCSP, componentList = [],
                        instructionList = PageInstructions { autoList = [inst3],
                          conditionalList = [] }, fileList = Map.empty }
          inst4 = Instruction (Right True) Rule { rType = RuleType Normal Full,
                    rMethod = Get, rUrl = Right "",
                    rContents= Map.fromList [("xrd:type",""),
                      ("openid.return_to", show url4)] }
          response4 = Response {destinationIdentifier = "", origin = url5,
                        resNonce = "", csp = emptyCSP, componentList = [],
                        instructionList = PageInstructions { autoList = [inst4],
                          conditionalList = [] }, fileList = Map.empty }
          inst5 = Instruction (Left 1) Rule { rType = RuleType Normal Full,
                    rMethod = Post, rUrl = Left url1,
                    rContents = Map.singleton "success!!" "?" }
          component5 = Component { cOrigin = url4, cList = [inst5], cPos = 1,
                         cVisible = True }
          response5 = Response {destinationIdentifier = "", origin = url4,
                        resNonce = "", csp = emptyCSP,
                        componentList = [component5],
                        instructionList = PageInstructions { autoList = [],
                        conditionalList = [] },
                        fileList = Map.singleton (Right url1)
                          WebFile { fTtl = 100,
                          fContent = Map.singleton "session" ""} }
          ruleMap = Map.fromList [(url1, [([], [], response1, Nothing)] ),
                    (url2, [(["openid_identity"], [srule2], response2,
                      Nothing)]),
                    (url4, [([], [], response3, Nothing),
                      (["openid.ns", "openid.mode", "openid.claimed_id",
                        "openid.identity", "openid.return_to",
                        "openid.response_nonce", "openid.assoc_handle",
                        "openid.signed"], [], response5, Nothing)]),
                    (url5, [([], [], response4, Nothing)])]

opServer :: String -> Server
opServer sName =
    initEmptyServer sName ["openid.response_nonce", "op_local_identifier",
      "openid.local_id", "openid.mac"] ("", [])
      ["openid.mac_key"] ["openid.response_nonce", "openid.dh_modulus",
      "openid.dh_gen", "openid.dh_consumer_public"] [] kData ruleMap
    where url1 = Url { server = sName, path = "something" }
          url2 = Url { server = sName, path = "two" }
          url3 = Url { server = sName, path = "three" }
          url4 = Url { server = sName, path = "four"}
          url5 = Url { server = sName, path = "five"}
          url6 = Url { server = sName, path = "six"}
          kData = Map.fromList [("id", ["userid"]),
                    ("credentials", ["uname pass"]), ("op",[sName]),
                    ("openid.ns", [show oid]), ("opened.mode", ["associate"]),
                    ("openid.assoc_type", ["HMAC-SHA256"]),
                    ("openid.session_type", ["stype"]),
                    ("openid.claimed_id", ["uname"]),
                    ("openid.identity", ["uname"])]
          emptyCSP = Csp { scriptList = [], frameList = [], resourceList = []}
          inst1_1 = Instruction (Right True)
                      Rule { rType = RuleType Normal Full, rMethod = Post,
                      rUrl = Right "",
                      rContents = Map.fromList [("op_local_identifier", ""),
                      ("claimed_identifier", ""), ("xrd:type", "Type"),
                      ("xrd:uri", show url2), ("local_id", "") ] }
          inst1_2 = Instruction (Right True)
                      Rule { rType = RuleType Normal Full, rMethod = Post,
                      rUrl = Left url3, rContents = Map.fromList
                        [("assoc", "assoc"), ("openid.ns", "?"),
                        ("opened.mode", "?"), ("openid.assoc_type", "?"),
                        ("openid.session_type", "?"),
                        ("openid.dh_modulus", "?"), ("openid.dh_gen", "?"),
                        ("openid.dh_consumer_public", "?")] }
          response1 = Response {destinationIdentifier = "", origin = url1,
                        resNonce = "", csp = emptyCSP, componentList = [],
                        instructionList = PageInstructions { autoList =
                          [inst1_1, inst1_2], conditionalList = [] },
                        fileList = Map.empty }
          inst2 = Instruction (Right True) Rule { rType = RuleType Normal Full,
                    rMethod = Post, rUrl = Right "",
                    rContents = Map.fromList [("openid.ns", ""),
                      ("openid.assoc_handle", ""), ("openid.session_type", ""),
                      ("openid.assoc_type", ""), ("openid.expires_in", "1000"),
                      ("openid.dh_server_public", ""), ("openid.mac_key", ""),
                      ("openid.mac", "")] }
          response2 = Response {destinationIdentifier = "", origin = url1,
                        resNonce = "", csp = emptyCSP, componentList = [],
                        instructionList = PageInstructions { autoList = [inst2],
                        conditionalList = [] }, fileList = Map.empty }
          srule3 = ServerRule { sReqMethod = Get,
                     sReqUrl =Right "openid.return_to",
                     sReqContents = [] }
          inst3 = Instruction (Left 1) Rule { rType = RuleType Normal Full,
                    rMethod = Post, rUrl = Left url5,
                    rContents = Map.fromList [("credentials", "?"),
                      ("openid.ns", ""), ("openid.mode", ""),
                      ("openid.claimed_id", ""), ("openid.identity", ""),
                      ("openid.assoc_handle", ""), ("openid.return_to", ""),
                      ("openid.realm", "")] }
          component3 = Component { cOrigin = url4, cList = [inst3], cPos = 1,
                                    cVisible = True}
          response3 = Response {destinationIdentifier = "", origin = url4,
                        resNonce = "", csp = emptyCSP,
                        componentList = [component3],
                        instructionList = PageInstructions { autoList = [],
                        conditionalList = [] }, fileList = Map.empty }
          inst4 = Instruction (Left 1) Rule { rType = RuleType Normal Full,
                  rMethod = Post, rUrl = Left url6,
                  rContents = Map.fromList [("openid.ns", ""),
                    ("openid.mode", ""), ("openid.claimed_id", ""),
                    ("openid.identity", ""), ("openid.return_to", ""),
                    ("openid.response_nonce", ""), ("openid.assoc_handle", ""),
                    ("openid.signed", "op_endpoint, identity, claimed_id, return_to, assoc_handle, response_nonce"),
                    ("openid.signature", "Sig op_endpoint, openid.identity, openid.claimed_id, openid.return_to, openid.assoc_handle, openid.response_nonce Pri " ++ sName)]}
          component4 = Component { cOrigin = url5, cList = [inst4], cPos = 1,
                                  cVisible = True}
          response4 =  Response {destinationIdentifier = "", origin = url5,
                        resNonce = "", csp = emptyCSP,
                        componentList = [component4],
                        instructionList = PageInstructions { autoList = [],
                        conditionalList = [] }, fileList = Map.empty }
          inst5 = Instruction (Left 1) Rule { rType = RuleType Normal Full,
                  rMethod = Post, rUrl = Right "openid.return_to",
                  rContents = Map.fromList [("openid.ns", ""),
                    ("openid.mode", ""), ("openid.claimed_id", ""),
                    ("openid.identity", ""), ("openid.return_to", ""),
                    ("openid.response_nonce", ""), ("openid.assoc_handle", ""),
                    ("openid.signed", ""),
                    ("openid.signature", "")]}
          component5 = Component { cOrigin = url6, cList = [inst5], cPos = 1,
                                cVisible = True}
          response5 =  Response {destinationIdentifier = "", origin = url6,
                      resNonce = "", csp = emptyCSP,
                      componentList = [component5],
                      instructionList = PageInstructions { autoList = [],
                      conditionalList = [] }, fileList = Map.empty }
          ruleMap = Map.fromList [
                      (url1, [(["openid_identity"], [], response1, Nothing)]),
                      (url3, [(["assoc", "openid.ns", "opened.mode",
                        "openid.assoc_type", "openid.session_type",
                        "openid.dh_modulus", "openid.dh_gen",
                        "openid.dh_consumer_public"], [], response2, Nothing)]),
                      (url4, [(["openid.ns", "openid.mode", "openid.claimed_id",
                        "openid.identity", "openid.assoc_handle",
                        "openid.return_to", "openid.realm"], [srule3], response3, Nothing)]),
                      (url5, [(["credentials", "openid.ns", "openid.mode",
                        "openid.claimed_id", "openid.identity",
                        "openid.assoc_handle", "openid.return_to",
                        "openid.realm"], [], response4, Nothing)]),
                      (url6, [(["openid.ns", "openid.mode", "openid.claimed_id",
                        "openid.identity", "openid.return_to",
                        "openid.response_nonce", "openid.assoc_handle",
                        "openid.signed", "openid.signature"], [], response5, Nothing)])]


getServers :: ([Server], [Either Request Response], Attacker)
getServers = ([s1,s2,s3], res, myAttacker)
    where s1 = opServer "op"
          s2 = rpServer "rp"
          s3 = rpServer "rp2"
          url1 = Url {server = "rp2", path = "one"}
          ret = Url { server = "rp2", path = "three" }
          emptyCSP = Csp { scriptList = [], frameList = [], resourceList = []}
          inst = Instruction (Left 1) Rule { rType = RuleType Normal Full,
                    rMethod = Post, rUrl = Left url1,
                    rContents = Map.singleton "success!!" "?" }
          component = Component { cOrigin = ret, cList = [inst], cPos = 1,
                         cVisible = True }
          pRes = Response { destinationIdentifier = "", origin = ret,
                        resNonce = "", csp = emptyCSP,
                        componentList = [component],
                        instructionList = PageInstructions { autoList = [],
                                            conditionalList = [] },
                        fileList = Map.singleton (Right url1)
                                     WebFile { fTtl = 3600,
                                     fContent = Map.singleton "session" "" }}
          res = [Right pRes { destinationIdentifier = "attacker" },
                 Right pRes { destinationIdentifier = "browser"}]
          aKnown = Map.fromList [("rp", "rp2")]
          myAttacker = initAttacker "attacker" True ["rp"] [] [s1,s2,s3] []
                   Map.empty aKnown
