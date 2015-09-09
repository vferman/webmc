{-
Project: WebMC: a model checker for the web
Author: Victor Ferman
File: Browser.hs
Description: This file defines browser's actions an capabilities, used in order
    to process requests and responses as a browser would, will give lists of
    actions that can be taken at any point in time, relies on the policies

-}

module Browser where

import qualified Data.List  as List
import qualified Data.Map   as Map
import           Data.Maybe
import Data.Either
import           Policies
import           Types


{-
    Functions in charge of instantiating browsers and of getting the actions
    that can be performed at any given time useful for the Planner
-}
getBrowserActions :: Browser -> [String]
getBrowserActions = browserActions

initBrowser :: String -> Visited -> Map.Map Url WebFile -> Maybe WebPage ->
  Maybe WebPage -> [(Nonce,Rule)] -> [Rule] -> [Int] -> Browser
initBrowser bID history cookies cWeb oWeb pRes pReq nonceL =
    Browser { browserIdentifier = bID, visitedPages = history, files = cookies,
      current = cWeb, original = oWeb, pendingResponses = pRes,
      pendingRequest = pReq, bNonceList = nonceL }

initEmptyBrowser:: String -> Browser
initEmptyBrowser bID =
    initBrowser bID history Map.empty Nothing Nothing [] [] [1..]
    where history = Visited { previous = [], next = [] }




{-
    Section in charge of miscellaneous functions that are useful
-}

--Function used to get the rule in an instruction
ruleFromInstruction:: Instruction -> Rule
ruleFromInstruction inst = rule
    where (Instruction _ rule) = inst

getRuleFromBrowser:: Browser -> Maybe Rule
getRuleFromBrowser cBrowser = rule
    where (Browser {pendingRequest = pendingReq}) = cBrowser
          rule = if null pendingReq then Nothing else Just $ head pendingReq

getIdFromBrowser:: Browser -> String
getIdFromBrowser cBrowser = bID
    where (Browser {browserIdentifier = bID, visitedPages = _, files = _,
            current = _, original = _, pendingResponses = _,
            pendingRequest = _, bNonceList = _}) = cBrowser


ruleToRequest:: Rule -> String -> Nonce -> Request
ruleToRequest cRule bID cNonce =
    Request { originIdentifier = bID, destination = ruleUrl,
      reqNonce = cNonce, method = cMethod, payload = rPayload}
    where ( Rule {rType = _, rMethod = cMethod, rUrl = Left ruleUrl,
            rContents = rPayload }) = cRule

--Function used to transform instructions to their corresponding requests
getRequest:: Browser-> (Browser,Maybe Request)
getRequest cBrowser
    | isNothing cRule = (Browser {browserIdentifier = bID, visitedPages = bVP,
                          files = bF, current = bCW, original = bOW,
                          pendingResponses = bPR, pendingRequest = bPReq,
                          bNonceList = bNL}, Nothing)
    | otherwise = (Browser {browserIdentifier = bID, visitedPages = bVP,
                    files = bF,current = bCW, original = bOW,
                    pendingResponses = bPR, pendingRequest = bPReq,
                    bNonceList = drop 1 bNL}, Just ( ruleToRequest
                      (fromJust cRule) bID nonce ))
    where (Browser {browserIdentifier = bID, visitedPages = bVP, files = bF,
            current = bCW, original = bOW, pendingResponses = bPR,
            pendingRequest = bPReq, bNonceList = bNL})= cBrowser
          cRule = getRuleFromBrowser cBrowser
          nonce = "nonce" ++ bID ++ show (head bNL)

--Fuction used to lookup if there is a request to a given url
lookupRule:: Url -> Nonce-> [(Nonce,Rule)] -> Maybe Rule
lookupRule _ _ [] = Nothing
lookupRule resUrl rNonce (x:xs)
    | resUrl == ruleUrl && rNonce == nonce = Just rule
    | otherwise = lookupRule resUrl rNonce xs
    where (nonce, rule) = x
          (Rule {rUrl = Left ruleUrl }) = rule


--Function to merge web files (e.g. cookies)
mergeFiles:: WebFile -> WebFile -> WebFile
mergeFiles new old =
    WebFile { fTtl = nttl, fContent = Map.union nfContents ofContents}
    where (WebFile { fTtl = nttl, fContent = nfContents })=new
          (WebFile { fContent = ofContents })=old


--Function creates a web page from a response
newWebFromResponse:: Response -> Maybe WebPage
newWebFromResponse response=
    Just WebPage { wOrigin = url, wCsp = rCsp, wElem = rcList,
      wInstructions = iList}
    where (Response { origin = url, csp=rCsp, componentList = rcList,
            instructionList = iList })= response


-- Function that adds instructions to web pages
addScriptToWeb :: Maybe WebPage -> PageInstructions-> Maybe WebPage
addScriptToWeb Nothing _ = Nothing
addScriptToWeb (Just webPage) script =
    Just WebPage { wOrigin = url, wCsp = rCsp, wElem = wcList,
       wInstructions = newInst}
    where (WebPage { wOrigin = url, wCsp = rCsp, wElem = wcList,
             wInstructions = (PageInstructions {autoList = aList,
             conditionalList = condList })}) = webPage
          (PageInstructions {autoList = sAutoList,
             conditionalList = sCondList}) = script
          newInst = PageInstructions {autoList = aList++sAutoList,
             conditionalList = condList ++ sCondList}


-- Fuction that adds a component to a web page, responses shouldn't have more
-- than one component unless they are a full web page, we just ignore the extra
addResourceToWeb:: Maybe WebPage -> [Component] -> Maybe WebPage
addResourceToWeb Nothing _ = Nothing
addResourceToWeb (Just webPage) [] = Just webPage
addResourceToWeb (Just webPage) (x:_) =
    Just WebPage { wOrigin = url, wCsp = rCsp, wElem = x:wcList,
             wInstructions = iList }
    where (WebPage { wOrigin = url, wCsp = rCsp, wElem = wcList,
             wInstructions = iList }) = webPage


-- Function that gets instrutions that should be executed right away
getRulesFromWeb:: Maybe WebPage -> [Rule]
getRulesFromWeb Nothing = []
getRulesFromWeb (Just webPage) = map ruleFromInstruction aList
    where (WebPage { wInstructions = PageInstructions { autoList = aList }})
            = webPage


{-
    Section in charge of what happens when the browser receives a response from
      the servers
-}


--Bulk of the actions performed when the browser receives a new response
--  its appart from responseReceived to avoid complex conditions
newBrowserFromResponse:: Browser -> Response -> Rule -> Browser
newBrowserFromResponse cBrowser response rule
    | sameOriginPolicy oUrl rule =
        Browser { browserIdentifier=bID, visitedPages = newVisitedWeb,
          files = Map.unionWith mergeFiles fList fInfo,
          current = newCurrentWeb, original = newOriginalWeb,
          pendingResponses = newPendingRes, pendingRequest = newPendingReq,
          bNonceList = bNL}
    | otherwise =
        Browser { browserIdentifier=bID, visitedPages = visitedWeb,
          files = Map.unionWith mergeFiles fList fInfo, current = cWeb,
          original = oWeb, pendingResponses = newPendingRes,
          pendingRequest = pendingReq, bNonceList=bNL }
    where (Browser {browserIdentifier=bID, visitedPages = visitedWeb,
             files = fInfo, current = cWeb, original = oWeb,
             pendingResponses = pendingRes, pendingRequest = pendingReq,
             bNonceList=bNL }) = cBrowser
          (Response { componentList = elemList, resNonce =rNonce,
             instructionList = iList, fileList =fList })= response
          (Rule {rType = RuleType _ cType })=rule
          (Just WebPage {wOrigin = oUrl }) = cWeb
          (Visited { previous = backList }) =visitedWeb
          (PageInstructions {autoList = resAutoList }) = iList
          newVisitedWeb
              | cType == Full = Visited { previous = oWeb:backList,
                                  next = [] }
              | otherwise = visitedWeb
          newCurrentWeb
              | cType == Full = newWebFromResponse response
              | cType == Frame = addResourceToWeb (addScriptToWeb cWeb iList)
                                   elemList
              | cType == Script = addScriptToWeb cWeb iList
              | otherwise = addResourceToWeb cWeb elemList
          newOriginalWeb = if cType == Full
                             then newCurrentWeb
                             else oWeb
          newPendingRes = if cType == Full
                            then []
                            else List.delete (rNonce, rule) pendingRes
          newPendingReq
              | cType == Full = getRulesFromWeb newOriginalWeb
              | cType == Script || cType == Frame =
                    pendingReq ++ map ruleFromInstruction resAutoList
              |otherwise = pendingReq


--Function that describes what to do when a new response is received
responseReceived::Browser -> Response -> Browser
responseReceived cBrowser response
    | isNothing rule = cBrowser
    | otherwise = newBrowserFromResponse cBrowser response (fromJust rule)
    where (Browser {pendingResponses = pendingRes }) = cBrowser
          url = origin response
          nonce = resNonce response
          rule = lookupRule url nonce pendingRes



{-
    Section in charge of what happens when the browser sends a request to a
      server
-}

ruleToResponses:: Maybe Rule -> Nonce -> [(Nonce, Rule)] -> [(Nonce,Rule)]
ruleToResponses Nothing _ responses = responses
ruleToResponses (Just rule) nonce responses
    | cType == Full = [(nonce,rule)]
    | otherwise = (nonce, rule):responses
    where (RuleType _ cType)=rType rule

requestSent::Browser -> Request -> Browser
requestSent cBrowser req =
    Browser {browserIdentifier=bID, visitedPages = visitedWeb, files = fInfo,
      current = currentWeb, original = originalWeb,
      pendingResponses = newPendingRes, pendingRequest = newPendingReq,
      bNonceList=bNL}
    where (Browser {browserIdentifier=bID, visitedPages = visitedWeb,
            files = fInfo, current = currentWeb, original = originalWeb,
            pendingResponses = pendingRes, pendingRequest = pendingReq,
            bNonceList = bNL}) = cBrowser
          rule = if null pendingReq
                   then Nothing
                   else Just (head pendingReq)
          newPendingRes = ruleToResponses rule (reqNonce req) pendingRes
          newPendingReq = if null pendingReq
                            then []
                            else tail pendingReq

{-
    section in charge of user input and how it transforms the browser
-}

--Auxiliar function that generates a new instruction in for the case of the
--  user inputing a new url
newRule:: Url -> Maybe WebFile-> Rule
newRule url Nothing =
    Rule {rType = RuleType Normal Full,
      rMethod=Get, rUrl=Left url, rContents=Map.empty}
newRule url (Just file) =
    Rule {rType = RuleType Normal Full,
      rMethod=Get, rUrl=Left url, rContents = fileContents}
    where (WebFile {fContent = fileContents })=file


--Auxiliar function that checks wheter an instruction has been triggered or not
isTriggered:: Pos -> Instruction -> Bool
isTriggered _ (Instruction (Right _) _ ) = False
isTriggered pos (Instruction (Left val) _ )= val == pos


--Auxiliar function that checks wheter a component was clicked on or not
elemTriggered:: Pos -> Component -> Bool
elemTriggered pos rComponent = pos == elemPos
    where (Component { cPos = elemPos }) = rComponent


--Auxiliar function that gathers the instructions from the components
getComponentInstructions:: Component -> [Instruction]
getComponentInstructions rComponent = instructions
     where (Component { cList = instructions }) = rComponent


--Auxiliar function that checks wheter all the information needed to carry out
--  an instruction is present
isComplete:: Instruction -> Bool
isComplete instruction = Map.null incompleteTerms
    where (Instruction _ (Rule {rContents = contents})) = instruction
          incompleteTerms = Map.filter (=="?") contents


--Auxiliar function that adds the user input to the instructions, it leaks
--  information from the user input to all of the triggered instructions
--  this is the intended behavior since we use compatibility instead of equality
--  and consider that scripts can get to said information
addDataToInstruction:: Known -> Instruction -> Instruction
addDataToInstruction information instruction =
    Instruction trigger Rule {rType = ruleType, rMethod = ruleMethod,
         rUrl = url, rContents = Map.union information contents}
    where (Instruction trigger (Rule {rType = ruleType, rMethod = ruleMethod,
             rUrl = url, rContents = contents})) = instruction


--Auxiliar function that gets the instructions that can be performed
--  depends on the input since there may be triggered instructions that cannot
--  be executed since they still require some information
getInstructionsForInput:: Maybe Known -> [Instruction] -> [Instruction]
getInstructionsForInput Nothing instructions =
    filter isComplete instructions
getInstructionsForInput (Just information) instructions=
    getInstructionsForInput Nothing instructions ++ completeForms
    where formInstructions = map (addDataToInstruction information) $
            filter (\inst -> not (isComplete inst)) instructions
          completeForms = filter isComplete formInstructions


--Auxiliar function that gets all of the instructions triggered by the user
--  when she performed and input actions (click or form) includes the
--  conditional instructions triggered in the web page and the components'
--  instructions
getRulesForPosition:: Pos -> Maybe Known -> [Instruction] -> [Component] -> [Rule]
getRulesForPosition pos formData instList components =
    map ruleFromInstruction $ triggeredInstructions ++ componentInstructions
    where triggeredInstructions= filter (isTriggered pos) instList
          triggeredComponents = filter (elemTriggered pos) components
          tmp = concatMap getComponentInstructions triggeredComponents
          componentInstructions = getInstructionsForInput formData tmp


--Function used to manage the state of the browser when receiving any of the
--  possible user inputs, returns the new state of the browser and a list of
--  instructions that need to be carried out
userInputReceived:: Browser -> UserInput -> Browser
userInputReceived cBrowser (Address url) =
    Browser {browserIdentifier = bID, visitedPages = visitedWeb, files = fInfo,
        current=currentWeb, original=originalWeb, pendingResponses=[],
        pendingRequest=[nRule], bNonceList = bNL }
    where (Browser {browserIdentifier=bID, visitedPages = visitedWeb,
            files = fInfo, current = currentWeb, original = originalWeb,
            bNonceList = bNL}) = cBrowser
          bData = Map.lookup url fInfo
          nRule = newRule url bData

userInputReceived cBrowser (Position pos) =
    Browser {browserIdentifier = bID, visitedPages = visitedWeb, files = fInfo,
        current=currentWeb, original=originalWeb, pendingResponses = pendingRes,
        pendingRequest = reqList, bNonceList = bNL}
    where (Browser {browserIdentifier=bID, visitedPages = visitedWeb,
            files = fInfo, current = currentWeb, original = originalWeb,
            pendingResponses = pendingRes, pendingRequest = pendingReq,
            bNonceList = bNL}) = cBrowser
          (Just (WebPage {wCsp = rCsp, wElem = components,
            wInstructions = (PageInstructions
            { conditionalList = condList }) })) = currentWeb
          rules = getRulesForPosition pos Nothing condList components
          reqList= filter (contentSecurityPolicy rCsp) $ rules++pendingReq

userInputReceived cBrowser (Form (FormInput knowledge pos)) =
    Browser {browserIdentifier = bID, visitedPages = visitedWeb, files = fInfo,
        current=currentWeb, original=originalWeb, pendingResponses = pendingRes,
        pendingRequest = reqList, bNonceList = bNL }
    where (Browser {browserIdentifier=bID, visitedPages = visitedWeb,
            files = fInfo, current = currentWeb, original = originalWeb,
            pendingResponses = pendingRes, pendingRequest = pendingReq,
            bNonceList = bNL }) = cBrowser
          (Just (WebPage {wCsp = rCsp, wElem = components,
            wInstructions = (PageInstructions
            { conditionalList = condList }) })) = currentWeb
          rules = getRulesForPosition pos (Just knowledge) condList components
          reqList= filter (contentSecurityPolicy rCsp) $ rules++pendingReq

userInputReceived cBrowser Back =
    Browser {browserIdentifier=bID,
        visitedPages = Visited { previous = xs, next = oWeb:forwardList },
        files = fInfo, current = x, original = x, pendingResponses = [],
        pendingRequest = reqList, bNonceList = bNL}
    where (Browser {browserIdentifier=bID,
            visitedPages = (Visited { previous = (x:xs), next = forwardList }),
            files = fInfo, original = oWeb, bNonceList = bNL }) = cBrowser
          aList = maybe [] (\wp -> autoList (wInstructions wp)) x
          reqList = map ruleFromInstruction aList

userInputReceived cBrowser Forward =
    Browser {browserIdentifier=bID,
       visitedPages = Visited { previous = oWeb:backList, next = ys },
       files = fInfo, current = y, original = y, pendingResponses = [],
       pendingRequest = reqList, bNonceList = bNL}
    where (Browser {browserIdentifier=bID,
            visitedPages = (Visited { previous = backList, next = (y:ys) }),
            files = fInfo, original = oWeb, bNonceList = bNL}) = cBrowser
          (Just (WebPage { wInstructions = (PageInstructions
            { autoList = aList }) })) = y
          reqList = map ruleFromInstruction aList


{-
    Section in charge of outputs to the user
-}

--Auxiliar funtion that to get Visibility of components
isVisible:: Component -> Bool
isVisible (Component { cVisible=value }) = value


--Auxiliar function to get what will be requested of the user in forms
instructionUserData::[Instruction]-> [String]
instructionUserData [] = []
instructionUserData (x:xs) = info++instructionUserData xs
    where (Instruction _ (Rule { rContents=contents }))=x
          info = Map.keys $ Map.filter (=="?") contents


--Auxiliar function for a fold, transforms a component to links and forms
fromComponent:: ([Int], [(Int, [String])]) -> Component -> ([Int], [(Int, [String])])
fromComponent (links, forms) component=
    if null dataList
        then (pos:links, forms)
        else (links, (pos, show myOrigin:dataList):forms)
    where (Component {cOrigin=myOrigin, cList=iList, cPos=pos})= component
          dataList= instructionUserData iList

--Auxiliar fuction to get the origin out of a web page
getLocation:: Maybe WebPage -> Url
getLocation Nothing = Url {server="", path="" }
getLocation (Just webPage) = rOrigin
    where (WebPage { wOrigin = rOrigin }) = webPage

--Auxiliar fuction to get the components out of a web page
getComponents:: Maybe WebPage -> [Component]
getComponents Nothing = []
getComponents (Just webPage) = rElem
    where (WebPage { wElem = rElem }) = webPage


--Auxiliar function gets a list of components and retunrs all the
--  corresponding links and forms
getDisplayElems:: [Component] -> ([Int], Map.Map Int [String])
getDisplayElems [] = ([], Map.empty)
getDisplayElems elemList = (links, Map.fromList forms)
    where (links,forms) = foldl fromComponent ([],[]) elemList


--Function used to generate the display for the user
generateDisplay ::Browser -> Display
generateDisplay cBrowser =
    Display { lock = True, location = originUrl,
       visibleLinks = vLinks, visibleForms = vForms, back = not (null backList),
       forward=not (null forwardList)}
    where (Browser { visitedPages = (Visited { previous = backList,
            next = forwardList}), current = cWeb })= cBrowser
          originUrl= getLocation cWeb
          currentComponents = getComponents cWeb
          (vLinks, vForms)=getDisplayElems $ filter isVisible currentComponents


browserActions :: Browser -> [String]
browserActions cBrowser
    | not (null req) = let r = either server id $ rUrl (head req)
                       in ["B -> "++ r ++": request"]
    | otherwise = []
    where req = pendingRequest cBrowser

browserOptionToEvent :: Browser -> String -> (Browser, Maybe Request)
browserOptionToEvent cBrowser input
    | last (words input) == "request" = getRequest cBrowser
    | otherwise = (cBrowser, Nothing)
