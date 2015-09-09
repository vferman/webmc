{-
Project: WebMC: a model checker for the web
Author: Victor Ferman
File: Types.hs
Description: This file defines all of the data types for our model checker, it
    includes principals, urls, knowledge, messages.

-}

module Types where

--import System.Random
import qualified Data.Map as Map

{-
    The definitions are constructive and as such, we will start by defining the
    basic blocks of the system and work from there to create more complex data
    definitions that are required
-}

-- Domains, may refer to a server or a family of servers
type Domain = String

--Nonces, either fresh or reused
type Nonce = String

--URLs used to distinguish servers and actions on those servers
data Url = Url { server :: Domain
               , path :: String
               } deriving(Show, Read, Eq, Ord)

emptyUrl :: Url
emptyUrl = Url { server = "", path ="" }

{-
    We start by defining what the user can do and what it receives,
    useful since the user knows little about the internal workings
    of all other participants and just sees snapshots of the current
    state of the system
-}
--output from the Browser to the User
--Used by the user to know what her options are to interact with the world
data Display = Display { lock :: Bool
                       , location :: Url
                       , visibleLinks :: [Int]
                       , visibleForms :: Map.Map Int [String]
                       , back:: Bool
                       , forward:: Bool
                       } deriving(Show, Eq)

-- a position in the display used to represent clicks
type Pos = Int

-- shorthand for a map that represents knowledge
type Known = Map.Map String String

-- data to be sent to the browser by the user
-- used to represent form submition
data FormInput = FormInput Known Pos deriving(Show, Eq)


-- Different kinds of user inputs, represents the possible actions of a user
data UserInput = Address Url | Position Pos | Form FormInput | Back | Forward
     deriving(Show, Eq)


{-
    After defining what the user interacts with we continue with the browser
    the browser is the most complicated principal and is the one that moves
    forward everything
-}


-- useful to diferentiate how a message will be created
data RequestType = Normal | Scripted deriving(Show, Eq, Ord)

-- useful to know what information is being requested
data ContentType = Full | Script | Frame | Resource deriving(Show, Eq, Ord)

-- combaining how and what is requested into a single chunk
data RuleType = RuleType RequestType ContentType deriving(Show, Eq, Ord)

-- represents the method/encodign the browser will use to send a message
data RequestMethod = Get | Post | Put | Delete deriving(Show, Eq, Ord)


-- represents whether an action is available or not
type Trigger = Either Pos Bool;

-- represents what is to be done by the browser at some future time
data Rule = Rule { rType :: RuleType
                 , rMethod :: RequestMethod
                 , rUrl :: Either Url String
                 , rContents :: Known
                 } deriving(Show, Eq, Ord)

data ServerRule = ServerRule { sReqMethod :: RequestMethod
                              , sReqUrl :: Either Url String
                              , sReqContents :: [String]
                              } deriving(Show, Eq, Ord)

-- represents Intructions to eventually be executed by the browser
data Instruction = Instruction Trigger Rule deriving (Show, Eq, Ord)

-- Things the browser has loaded and the user may interact with
data Component = Component { cOrigin :: Url
                           , cList :: [Instruction]
                           , cPos :: Pos
                           , cVisible :: Bool
                           } deriving(Show, Eq, Ord)

-- Content Security Policies, the browser uses these in order to decide whether
-- the a request for certain content type can be made to some URL
data Csp = Csp { scriptList :: [Domain]
               , frameList :: [Domain]
               , resourceList :: [Domain]
               } deriving(Show, Eq, Ord)

-- Lists of instructions received when first requesting a web page
data PageInstructions = PageInstructions { autoList :: [Instruction]
                                         , conditionalList :: [Instruction]
                                         } deriving(Show, Eq, Ord)

-- Web page, with all of the information in contains
data WebPage = WebPage { wOrigin :: Url
                       , wCsp :: Csp
                       , wElem :: [Component]
                       , wInstructions :: PageInstructions
                       } deriving(Show, Eq)


-- Used to represent cookies and other information storage options
data WebFile = WebFile { fTtl :: Int
                       , fContent :: Known
                       } deriving(Show, Eq, Ord)

-- Used to represent history in browsers
data Visited = Visited { previous :: [Maybe WebPage]
                       , next :: [Maybe WebPage]
                       } deriving(Show, Eq)

-- A response is what a Browser receives from a server, it may contain:
data Response = Response { destinationIdentifier :: String
                         , origin :: Url
                         , resNonce :: Nonce
                         , csp :: Csp
                         , componentList :: [Component]
                         , instructionList :: PageInstructions
                         , fileList :: Map.Map Url WebFile
                         } deriving(Show, Eq, Ord)

-- A request is the output from a browser to a server, it contains
data Request = Request { originIdentifier :: String
                       , destination :: Url
                       , reqNonce :: Nonce
                       , method :: RequestMethod
                       , payload :: Known
                       } deriving(Show, Eq, Ord)

defaultRequest :: Request
defaultRequest = Request { originIdentifier = "",
                   destination = Url { server = "", path = ""}, reqNonce = "",
                   method = Get, payload = Map.empty }

-- Now that we have definead all inputs and outputs we can represent events
data Message = Input UserInput | Output Display | WebRequest Request | WebResponse Response deriving(Show, Eq)

{-
    section used to define the characteristics of the different principals
-}

type UserKnowledge = Map.Map Domain Known

data User = User { userIdentifier :: String
                 , generalKnowledge :: Known
                 , domainKnowledge :: UserKnowledge
                 , knownUrls :: [Url]
                 } deriving(Show, Eq)

data Browser = Browser { browserIdentifier :: String
                       , visitedPages :: Visited
                       , files :: Map.Map Url WebFile
                       , current :: Maybe WebPage
                       , original :: Maybe WebPage
                       , pendingResponses :: [(Nonce, Rule)]
                       , pendingRequest :: [Rule]
                       , bNonceList :: [Int]
                       } deriving(Eq)

data Server = Server { serverIdentifier :: String
                     , autoGenerated :: [String]
                     , serverKnowledge :: Map.Map Domain Known
                     , serverSession :: Map.Map Nonce Known
                     , serverRules :: Map.Map Url [([String], [ServerRule],
                         Response)]
                     , pendingSRequests :: Map.Map Nonce [ServerRule]
                     , expectedResponses :: Map.Map Nonce (Nonce, Request)
                     , pendingSResponses :: Map.Map Nonce Response
                     , sNonceList :: [Int]
                     } deriving(Eq)

data Attacker = Attacker { attackerIdentifier :: String
                         , serverIDs :: [String]
                         , goal :: Request
                         , generated :: [String]
                         , acquiredInfo :: Map.Map String Known
                         , attackerKnowledge :: Known
                         , aNonceList :: [Int]
                         } deriving(Eq)

-- state of the system
data State = State { user :: User
                   , browser :: Browser
                   , servers :: [Server]
                   , attacker :: Attacker
                   } deriving(Show, Eq)

stringToPos:: String -> Pos
stringToPos str = read str::Pos

instance Show Browser where
    show Browser { browserIdentifier = bID, visitedPages = bVisited,
      files = bFiles, current = bCW, original = bOW, pendingResponses = bPR,
      pendingRequest = bPReq, bNonceList = bNL}
      =
      "Browser { browserIdentifier = " ++ bID ++ " visitedPages = " ++
        show bVisited ++ " files = " ++ show bFiles ++ " current = " ++ show bCW
        ++ " original = " ++ show bOW ++ " pendingResponses = " ++ show bPR ++
        " pendingRequest = " ++ show bPReq ++ " bNonceList = [" ++ show
        (head bNL) ++ "...] }"

instance Show Server where
    show Server { serverIdentifier = sID, autoGenerated = autoGen,
           serverKnowledge = sKnown, serverSession = sSession,
           serverRules = sRules, pendingSRequests = pReqs,
           expectedResponses = eRes, pendingSResponses = pRes,
           sNonceList = sNL }
      =
      "Server { serverIdentifier = "++ sID ++ "\nautoGenerated = " ++
      show autoGen ++ "\nserverKnowledge = " ++ show sKnown ++
      "\nServerSession = " ++ show sSession ++ "\nserverRules =" ++
      show sRules ++ "\nPendingSRequests = " ++ show pReqs ++
      "\nexpectedResponses = " ++ show eRes ++"\npendingSResponses =" ++
      show pRes ++ "\n sNonceList = [" ++show (head sNL) ++ "...] }"

instance Show Attacker where
    show Attacker { attackerIdentifier = aID, serverIDs = sIDs, goal = sGoal,
           generated = autoGen, acquiredInfo = aInfo,
           attackerKnowledge = aKnown, aNonceList =aNL}
      =
      "Attacker { attackerIdentifier = "++ aID ++ " controlled_servers = " ++
      show sIDs ++ "security_goal =" ++ show sGoal ++ "autoGenerated = " ++
      show autoGen ++ "acquired information = " ++ show aInfo ++
      "attackerKnowledge ="++ show aKnown ++ "aNonceList = [" ++
      show (head aNL) ++ "...] }"
