from typing import final
from django.shortcuts import render, HttpResponse, redirect
from datetime import datetime
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth import logout, authenticate, login
from matplotlib import gridspec
from pymongo import MongoClient
from email import message
from email.policy import HTTP
from lib2to3.pgen2.tokenize import generate_tokens
import re

import datetime
import pytz
from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.http import HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from gfg import settings
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode 
from django.utils.encoding import force_bytes, force_str
from . tokens import generate_token
from django.core.mail import EmailMessage, send_mail
from django.utils.http import urlsafe_base64_decode
from neo4j import GraphDatabase

import requests
from authentication.models import Contribute
import cdata.zohocrm as mod1
import cdata.freshdesk as mod2
import cdata.salesforce as mod3
import cdata.jira as mod4
from json import dumps
import nltk
from nltk import tokenize
from operator import itemgetter
import math
from nltk.stem.porter import PorterStemmer
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

nltk.download('stopwords')
nltk.download('punkt')
stop_words = list(set(stopwords.words('english')))


global_First_Name=""
uniqueId=""
uName=""
emailId=""
ppsummary=""
ppdescription=""
pproducts=[]
pkanalysis=""
pkinsisghts=""
powner=""
pptype=""


taggs=dict()
finaltags=[]
uniqueId2=""


# Create your views here.
def index(request):
    #making a conn variable to connect with database
    conn = MongoClient()
    db=conn.Lucid  #lucid is our database name
    collection=db.knowledge   #knowledge is collection name
    coll =collection.find()
    a = {'defectdata': coll.clone()}    #making a dictionary for display purpose
    new_data_dic = {}   # making this dictionary for pagination
    key = 1
    i = 0
    # list_of_attributes = ["ptype", "psummary", "pdescription","products","kanalysis","kinsisghts","tags","owner","ID"]
    for doc in coll:
        keys = str(key)
        lst = []
        new_data_dic[keys] = lst
        for k,v in doc.items():
            if k!='_id':
                # for products mapped and tags as they are not string but list type
                if type(v) == list :
                    flag = 1
                    for p in v:
                        if flag==1:
                            v =  "\n"+k.upper() + " : "  + p
                            flag=0
                        else:
                            #flag = 0
                            v += ", " + p 
                else:
                    v = v.replace(".","")
                    v = "\n"+k.upper() + " : " + v 
                new_data_dic[keys].append(v)
        key+=1      

    dataJSON = dumps(new_data_dic)


    return render(request, "authentication/index.html", {'data': dataJSON})


def signup(request):
    # method is post so that platform can get details from user
    if request.method == "POST":
        # global username 
        username = request.POST.get('username')
        fname = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        pass1 = request.POST['pass1']
        

        #several exceptions for validation 
        if User.objects.filter(username=username):
            messages.error(request, "Username already exist! Please try some other username")
            return redirect('home')
            
        if User.objects.filter(email=email):
            messages.error(request, "Email already registered!")
            return redirect('home')
        
     
        myuser = User.objects.create_user(username, email, pass1)
        myuser.first_name = fname
        myuser.last_name = lname
        myuser.is_active = False
        myuser.save()
        global uName
        uName = fname
        global emailId
        emailId = email 

        
        messages.success(request, " We have sent account activation link to your registered mail id. Kindly click on the link to activate your account .")
                
        
        #Email Address confirmation email
        
        current_site = get_current_site(request)
        email_subject = "Confirm your email @ Knowledge Platform"
        message2 = render_to_string('email_confirmation.html',{
            'name':myuser.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser)
        })
        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [myuser.email],
        )
        email.fail_silently = True
        email.content_subtype = "html"
        email.send()
        
        return redirect('signin')
    
    return render(request, "authentication/signup.html")


def delete_account(request):
    global uName #taking username from signin
    print(uName)
    global emailId #taking email from signin
    print(emailId)
    user = User.objects.get(username = uName)
    user.delete()
    messages.success(request, "Account Deleted Successfully")
    email_subject = "Account Delete Notification"
    message2 = render_to_string('delete_account.html',{
        'name':uName,
    })
    email = EmailMessage(
        email_subject,
        message2,
        settings.EMAIL_HOST_USER,
        [emailId],
    )
    email.fail_silently = True
    email.content_subtype = "html"
    email.send()
    
    return redirect('home')

def contribute(request):
    #taking data from user for various attributes of knowledge

    if request.method == "POST":
        ptype=request.POST['ptype']
        psummary=request.POST['psummary']
        pdescription=request.POST['pdescription']
        global ppsummary 
        global ppdescription
        ppsummary = psummary
        ppdescription = pdescription
        products=request.POST.getlist('CD')
        kanalysis=request.POST['kanalysis']
        kinsisghts=request.POST['kinsisghts']
        #tags=request.POST['tags']
        owner=request.POST['owner']     
        global pproducts, pkanalysis,pkinsisghts,powner,pptype, finaltags
        pproducts=products
        pkanalysis=kanalysis
        pkinsisghts=kinsisghts
        powner=owner
        pptype=ptype
        datetime_entry = datetime.datetime.now() 
        # username = request.session.get('username') 
        #contr=Contribute(ptype=ptype,psummary=psummary,pdescription=pdescription,products=products,kanalysis=kanalysis,kinsisghts=kinsisghts,tags=tags,owner=owner)
        contr=Contribute(ptype=ptype,psummary=psummary,pdescription=pdescription,products=products,kanalysis=kanalysis,kinsisghts=kinsisghts,owner=owner)
        contr.save()
        conn = MongoClient()
        db=conn.Lucid
        collection=db.knowledge
        
        #making a collection to send to mongo database
        rec1={
        #   "username":username1,          
          "ptype":ptype,
          "psummary":psummary,
          "pdescription":pdescription,
          "products":products,
          "kanalysis":kanalysis,
          "kinsisghts":kinsisghts,
          "tags":finaltags,
          "owner":owner,
          "ID" : owner[:3] + str(len(psummary)) + str(len(pdescription)) +str(len(kinsisghts) + len(kanalysis)),          

        }

        global uniqueId2
        #making a unique id for indexing purpose
        uniqueId2=owner[:3] + str(len(psummary)) + str(len(pdescription)) +str(len(kinsisghts) + len(kanalysis))
        collection.insert_one(rec1)
        tags_string=""
        for i in finaltags:
            tags_string+=i+","   
        print(finaltags,"finaaaaaaaaal",tags_string)     

        bgid="NA"
        generateTags(pdescription,psummary,kanalysis,kinsisghts,products)
        p2=""
        for i in products:
            p2+=i+","
        p2=p2[:-1]
        #contri_to_neo(pdescription,psummary,products, kanalysis,kinsisghts,owner,ptype, uniqueId2,finaltags)
        contri_to_neo(pdescription,psummary,p2, kanalysis,kinsisghts,owner,ptype, uniqueId2,finaltags,bgid)
        messages.success(request, 'Your message has been sent!')
        return redirect("home")
    return render(request, 'authentication/contribute.html')

def generateTags(a,b,c,d,products):   
    #stopwords for removing less important words from document
    more_stop_words = ["weren't", 'needn', "mustn't",'8;', '2)on', "needn't", 'haven', "wouldn't", 'most', 'only', 'down', 'over', 'mightn', 'where', 'this', 'your', "shouldn't", "you'll", 'so', 'weren', 'will', 'hadn', 'hasn', 'i', 'no', 'which', 'has', 'those', 'itself', 'they', 'whom', 'that', 'isn', 'couldn', 'as', 'doesn', "haven't", 'other', 'too', 'inserting', 'running', 'showing', 'picking', '3)query', 'calllogs', '(outcome', 'starttime', 'endtime', 'than', 'is', 'his', "don't", 'mustn', 'she', 'just', "hadn't", 'through', 'been', 'an', 'with', 'more', 'from', 'few', 'how', 'own', 't', 'were','template', 'being', 'above', 'both', 'it', "hasn't", 'these', 'wouldn', 'during', 'our', 'didn', 'all', 'should', "didn't", 'further', 'or', 'have', 'in', 'her', 'here', 'yourselves', 'did', 'a', 'its', 'of', 'about', "couldn't", "should've", 'after', 'some', 'the', 'at', 'be', 'aren', 'each', 'shan', 'won', 'he', 'my', 'why', 've', 'same', "doesn't", 's', 'up', 'now', 'ain', 'we', "shan't", 'what', 'below', 'then', 'such', "mightn't", 'me', 'out', 'do', "she's", 'm', "it's", "that'll", "isn't", 'y', 'yours', 'against', 'into', 'herself', 'under', 'who', 'wasn', 'by', "aren't", 'any', 'are', 'does', 'but', 'because', 'and', 'doing', 'until', 'off', 'very', "you'd", 'ourselves', 'was', 'once', 're', 'between', 'him', 'd', 'myself', 'can', 'ma', 'if', 'for', 'yourself', 'o', 'them', 'am', "you've", 'nor', 'don', 'you', 'when', 'had', 'on', 'not', "wasn't", "won't", 'ours', 'before', 'while', 'himself', 'themselves', 'shouldn', "you're", 'to', 'having', 'their', 'again', 'theirs', 'there', 'hers', 'll', ' able', 'about', 'above', 'abroad', 'according', 'accordingly', 'across', 'actually', 'adj', 'after', 'afterwards', 'again', 'against', 'ago', 'ahead', "ain't", 'all', 'allow', 'allows', 'almost', 'alone', 'along', 'alongside', 'already', 'also', 'although', 'always', 'am', 'amid', 'amidst', 'among', 'amongst', 'an', 'and', 'another', 'any', 'anybody', 'anyhow', 'anyone', 'anything', 'anyway', 'anyways', 'anywhere', 'apart', 'appear', 'appreciate', 'appropriate', 'are', "aren't", 'around', 'as', "a's", 'aside', 'ask', 'asking', 'associated', 'at', 'available', 'away', 'awfully', 'back', 'backward', 'backwards', 'be', 'became', 'because', 'become', 'becomes', 'becoming', 'been', 'before', 'beforehand', 'begin', 'behind', 'being', 'believe', 'below', 'beside', 'besides', 'best', 'better', 'between', 'beyond', 'both', 'brief', 'but', 'by', 'came', 'can', 'cannot', 'cant', "can't", 'caption', 'cause', 'causes', 'certain', 'certainly', 'changes', 'clearly', "c'mon", 'co', 'co.', 'com', 'come', 'comes', 'concerning', 'consequently', 'consider', 'considering', 'contain', 'containing', 'contains', 'corresponding', 'could', "couldn't", 'course', "c's", 'currently', 'dare', "daren't", 'definitely', 'described', 'despite', 'did', "didn't", 'different', 'directly', 'do', 'does', "doesn't", 'doing', 'done', "don't", 'down', 'downwards', 'during', 'each', 'edu', 'eg', 'eight', 'eighty', 'either', 'else', 'elsewhere', 'end', 'ending', 'enough', 'entirely', 'especially', 'et', 'etc', 'even', 'ever', 'evermore', 'every', 'everybody', 'everyone', 'everything', 'everywhere', 'ex', 'exactly', 'example', 'except', 'fairly', 'far', 'farther', 'few', 'fewer', 'fifth', 'first', 'five', 'followed', 'following', 'follows', 'for', 'forever', 'former', 'formerly', 'forth', 'forward', 'found', 'four', 'from', 'further', 'furthermore', 'get', 'gets', 'getting', 'given', 'gives', 'go', 'goes', 'going', 'gone', 'got', 'gotten', 'greetings', 'had', "hadn't", 'half', 'happens', 'hardly', 'has', "hasn't", 'have', "haven't", 'having', 'he', "he'd", "he'll", 'hello', 'help', 'hence', 'her', 'here', 'hereafter', 'hereby', 'herein', "here's", 'hereupon', 'hers', 'herself', "he's", 'hi', 'him', 'himself', 'his', 'hither', 'hopefully', 'how', 'howbeit', 'however', 'hundred', "i'd", 'ie', 'if', 'ignored', "i'll", "i'm", 'immediate', 'in', 'inasmuch', 'inc', 'inc.', 'indeed', 'indicate', 'indicated', 'indicates', 'inner', 'inside', 'insofar', 'instead', 'into', 'inward', 'is', "isn't", 'it', "it'd", "it'll", 'its', "it's", 'itself', "i've", 'just', 'k', 'keep', 'keeps', 'kept', 'know', 'known', 'knows', 'last', 'lately', 'later', 'latter', 'latterly', 'least', 'less', 'lest', 'let', "let's", 'like', 'liked', 'likely', 'likewise', 'little', 'look', 'looking', 'looks', 'low', 'lower', 'ltd', 'made', 'mainly', 'make', 'makes', 'many', 'may', 'maybe', "mayn't", 'me', 'mean', 'meantime', 'meanwhile', 'merely', 'might', "mightn't", 'mine', 'minus', 'miss', 'more', 'moreover', 'most', 'mostly', 'mr', 'mrs', 'much', 'must', "mustn't", 'my', 'myself', 'name', 'namely', 'nd', 'near', 'nearly', 'necessary', 'need', "needn't", 'needs', 'neither', 'never', 'neverf', 'neverless', 'nevertheless', 'new', 'next', 'nine', 'ninety', 'no', 'nobody', 'non', 'none', 'nonetheless', 'noone', 'no-one', 'nor', 'normally', 'not', 'nothing', 'notwithstanding', 'novel', 'now', 'nowhere', 'obviously', 'of', 'off', 'often', 'oh', 'ok', 'okay', 'old', 'on', 'once', 'one', 'ones', "one's", 'only', 'onto', 'opposite', 'or', 'other', 'others', 'otherwise', 'ought', "oughtn't", 'our', 'ours', 'ourselves', 'out', 'outside', 'over', 'overall', 'own', 'particular', 'particularly', 'past', 'per', 'perhaps', 'placed', 'please', 'plus', 'possible', 'presumably', 'probably', 'provided', 'provides', 'que', 'quite', 'qv', 'rather', 'rd', 're', 'really', 'reasonably', 'recent', 'recently', 'regarding', 'regardless', 'regards', 'relatively', 'respectively', 'right', 'round', 'said', 'same', 'saw', 'say', 'saying', 'says', 'second', 'secondly', 'see', 'seeing', 'seem', 'seemed', 'seeming', 'seems', 'seen', 'self', 'selves', 'sensible', 'sent', 'serious', 'seriously', 'seven', 'several', 'shall', "shan't", 'she', "she'd", "she'll", "she's", 'should', "shouldn't", 'since', 'six', 'so', 'some', 'somebody', 'someday', 'somehow', 'someone', 'something', 'sometime', 'sometimes', 'somewhat', 'somewhere', 'soon', 'sorry', 'specified', 'specify', 'specifying', 'still', 'sub', 'such', 'sup', 'sure', 'take', 'taken', 'taking', 'tell', 'tends', 'th', 'than', 'thank', 'thanks', 'thanx', 'that', "that'll", 'thats', "that's", "that've", 'the', 'their', 'theirs', 'them', 'themselves', 'then', 'thence', 'there', 'thereafter', 'thereby', "there'd", 'therefore', 'therein', "there'll", "there're", 'theres', "there's", 'thereupon', "there've", 'these', 'they', "they'd", "they'll", "they're", "they've", 'thing', 'things', 'think', 'third', 'thirty', 'this', 'thorough', 'thoroughly', 'those', 'though', 'three', 'through', 'throughout', 'thru', 'thus', 'till', 'to', 'together', 'too', 'took', 'toward', 'towards', 'tried', 'tries', 'truly', 'try', 'trying', "t's", 'twice', 'two', 'un', 'under', 'underneath', 'undoing', 'unfortunately', 'unless', 'unlike', 'unlikely', 'until', 'unto', 'up', 'upon', 'upwards', 'us', 'use', 'used', 'useful', 'uses', 'using', 'usually', 'v', 'value', 'various', 'versus', 'very', 'via', 'viz', 'vs', 'want', 'wants', 'was', "wasn't", 'way', 'we', "we'd", 'welcome', 'well', "we'll", 'went', 'were', "we're", "weren't", "we've", 'what', 'whatever', "what'll", "what's", "what've", 'when', 'whence', 'whenever', 'where', 'whereafter', 'whereas', 'whereby', 'wherein', "where's", 'whereupon', 'wherever', 'whether', 'which', 'whichever', 'while', 'whilst', 'whither', 'who', "who'd", 'whoever', 'whole', "who'll", 'whom', 'whomever', "who's", 'whose', 'why', 'will', 'willing', 'wish', 'with', 'within', 'without', 'wonder', "won't", 'would', "wouldn't", 'yes', 'yet', 'you', "you'd", "you'll", 'your', "you're", 'yours', 'yourself', 'yourselves', "you've", 'zero', 'a', "how's", 'i', "when's", "why's", 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'uucp', 'w', 'x', 'y', 'z', 'I', 'www', 'amount', 'bill', 'bottom', 'call', 'computer', 'con', 'couldnt', 'cry', 'de', 'describe', 'detail', 'due', 'eleven', 'empty', 'fifteen', 'fifty', 'fill', 'find', 'fire', 'forty', 'front', 'full', 'give', 'hasnt', 'herse', 'himse', 'interest', 'itse”', 'mill', 'move', 'myse”', 'part', 'put', 'show', 'side', 'sincere', 'sixty', 'system', 'ten', 'thick', 'thin', 'top', 'twelve', 'twenty', 'abst', 'accordance', 'act', 'added', 'adopted', 'affected', 'affecting', 'affects', 'ah', 'announce', 'anymore', 'apparently', 'approximately', 'aren', 'arent', 'arise', 'auth', 'beginning', 'beginnings', 'begins', 'biol', 'briefly', 'ca', 'date', 'ed', 'effect', 'et-al', 'ff', 'fix', 'gave', 'giving', 'heres', 'hes', 'hid', 'home', 'id', 'im', 'immediately', 'importance', 'important', 'index', 'information', 'invention', 'itd', 'keys', 'kg', 'km', 'largely', 'lets', 'line', "'ll", 'means', 'mg', 'million', 'ml', 'mug', 'na', 'nay', 'necessarily', 'nos', 'noted', 'obtain', 'obtained', 'omitted', 'ord', 'owing', 'page', 'pages', 'poorly', 'possibly', 'potentially', 'pp', 'predominantly', 'present', 'previously', 'primarily', 'promptly', 'proud', 'quickly', 'ran', 'readily', 'ref', 'refs', 'related', 'research', 'resulted', 'resulting', 'results', 'run', 'sec', 'section', 'shed', 'shes', 'showed', 'shown', 'showns', 'shows', 'significant', 'significantly', 'similar', 'similarly', 'slightly', 'somethan', 'specifically', 'state', 'states', 'stop', 'strongly', 'substantially', 'successfully', 'sufficiently', 'suggest', 'thered', 'thereof', 'therere', 'thereto', 'theyd', 'theyre', 'thou', 'thoughh', 'thousand', 'throug', 'til', 'tip', 'ts', 'ups', 'usefully', 'usefulness', "'ve", 'vol', 'vols', 'wed', 'whats', 'wheres', 'whim', 'whod', 'whos', 'widely', 'words', 'world', 'youd', 'youre', 'size', 'problem', 'set', 'include', 'custom', 'false', 'able', 'facing', 'issue', 'connecting', 'working', '', '#', '!', '@', '$', '%', '^', '·', '&', '*', '(', ')', '_', '-', '+', '=', '~', '`', ',', '.', '?', '/', ':', ';', 'execute', 'customer', 'wants', 'improve', 'information', 'like', 'create', 'high', 'contains', 'data', 'server', 'when', 'hi', 'hey', 'hello', 'error', 'good', 'user', 'add', 'attempt', 'we', 'lot', 'its', 'use', 'such', 'make', 'record', 'return', 'message', 'example', 'name', 'you', 'handling', 'found', 'that', 'received', 'getting', 'setting', 'large', 'small', 'tiny', 'huge', 'big', 'contain', 'made', 'new', 'address', 'attempt', 'please', 'hi,', 'hello,', 'hey,', 'so,', 'so', 'since', 'suggest', 'has', 'have', 'had', 'this', 'do', 'done', 'go', 'to', 'went', 'though', 'saved', 'although', 'generally', 'literally', 'enter', 'enters', 'center', 'same', 'if', 'else', 'for', 'while', '', '',"#", "!", "@", "$", "%", "^",'·', "&", "*", "(", ")", "_", "-", "+", "=", "~", "`",",", ".", "?","/", ":", ";", "execute", "customer", "wants", "improve",   "information","like","create", "high", "contains", "data", "server", "when", "hi", "hey", "hello", "error", "good" , "user", "add", "attempt", "we", "lot" , "its", "use", "such", "make", "record", "return", "message", "example", "name", "you", "handling", "found", "that", "received", "getting", "setting", "large", "small", "tiny", "huge", "big","contain", "made", "new", "address", "attempt","please","hi," ,"hello,","hey,","so,","so", "since", "suggest", "has", "have", "had", "this", "do", "done", "go", "to", "went", "though","saved", "although", "generally", "literally", "enter", "enters", "center", "same", "if", "else", "for", "while","heavy","asked", "share", "path",'maintain', 'multiple', 'place', 'templatefile','2020', '2021', 'longer', 'recognized', 'valid','code', 'returned', 'inquiry', 'property' ,'occurs', 'retrieving', 'object', 'checked','true', 'returns','handled', 'work', 'function','existing', 'migrate', 'planning', 'release', 'replace', 'bit', 'careful', '{',');','properly', 'updating', 'fetch', 'rahul',';','on']
    for w in more_stop_words:
        stop_words.append(w)
    print("stop_words list contains "+str(len(stop_words))+" words")

    #making a string from various attributes of knowledge
    s =  a+" " +b+" " +c+" " +d
    
    print(s)
    doc = s.lower()
    
    #Making the test case optimised

    for product in products:
        doc+=" " + product


    doc = doc.lower()
    doc = doc.replace(","," ")
    doc = doc.replace("'"," ")
    doc = doc.replace('"', " ")
    doc = doc.replace(":"," ")
    doc = doc.replace("="," ")

    # Step 1 : Find total words in the document
    total_words = doc.split()
    total_word_length = len(total_words)
    print(total_word_length)

    # Step 2 : Find total number of sentences
    total_sentences = tokenize.sent_tokenize(doc)
    total_sent_len = len(total_sentences)
    print(total_sent_len)

    # Step 3: Calculate TF for each word
    tf_score = {}
    for each_word in total_words:
        each_word = each_word.replace('.','')
        if each_word not in stop_words:
            if each_word in tf_score:
                tf_score[each_word] += 1
            else:
                tf_score[each_word] = 1
    print(tf_score)

    # Dividing by total_word_length for each dictionary element
    tf_score.update((x, y/int(total_word_length)) for x, y in tf_score.items())

    print(tf_score)
    # Check if a word is there in sentence list
    def check_sent(word, sentences): 
        final = [all([w in x for w in word]) for x in sentences] 
        sent_len = [sentences[i] for i in range(0, len(final)) if final[i]]
        return int(len(sent_len))


    # Step 4: Calculate IDF for each word
    idf_score = {}
    for each_word in total_words:
        each_word = each_word.replace('.','')
        if each_word not in stop_words:
            if each_word in idf_score:
                idf_score[each_word] = check_sent(each_word, total_sentences)
            else:
                idf_score[each_word] = 1

    # Performing a log and divide
    idf_score.update((x, math.log(int(total_sent_len)/y)) for x, y in idf_score.items())

    print(idf_score)
    # Step 5: Calculating TF*IDF
    tf_idf_score = {key: tf_score[key] * idf_score.get(key, 0) for key in tf_score.keys()} 
    print(tf_idf_score)
    # Get top N important words in the document
    n = len(tf_idf_score)
    tf_idf_score = dict(sorted(tf_idf_score.items(), key = itemgetter(1), reverse = True)[:n]) 
    
    print()
    print()
    print("The tags for the given doc are:")
    
    result=[]
    c = 10
    for k in tf_idf_score.keys():
        k = k.upper()
        result.append(k)

    print(result)


    #making a dictionary for saving to database
    tags = {"tag" : []}
    
    # Comment out this if you want traditional tags
    # keywords = ['CData Drivers','Drivers','ArcESB','Connect', 'Sync', 'Server', 'CData ArcESB', 'CData Connect', 'CData Sync', 'CData Server', 'CData DBAmp', 'DBAmp' , 'connect', 'automate', 'integrate', ' java', 'python', 'sql', 'cypher', 'c', '.net', 'driver', 'cloud', 'sync', 'arcesb', 'odbc', 'jdbc', 'saas', 'delphi', 'sdk', 'tableau', 'ado.net', 'ssis', 'jira', 'zoho', 'salesforce', 'freshdesk', 'defect', 'support', ' enhancement', ' opportunity', 'api', 'server', 'dbamp', 'adp', 'aws', 'azure', 'crm', 'amazon', 'mongo', 'mongodb', ' cassandra', 'cockroachdb', 'dropbox', 'email', 'github', 'graphql', 'mysql', 'sqlite', 'bigdata', ' hadoop', 'netsuite', 'sap', 'oracle', 'shipstation', 'wordpress', 'zendesk', 'xml', 'sybase', 'slack', 'sharepoint', 'rest', 'redshift', 'postgre', 'postgresql', 'paypal', 'onedrive', 'kafka', 'hdfs', 'couchdb', 'cosmos', 'bugzilla', 'adp', 'act-on', 'acumatica', 'alfresco', 'athena', 'dynamodb', 'avalara', 'bigcommerce', 'bigquery', 'digitalocean', 'docusign', 'elastisearch', 'evernote', 'facebook', 'hbase', 'hubspot', 'harperdb', 'hpcc', 'ibm', 'ldap', 'myob', 'magento', 'mailchimp', 'mariadb', 'marketo', 'microsoft', 'odata', 'parquet', ' accounting', 'erp', 'nosql', ' collaboration', ' e-commerce', 'api', 'teradata', 'singlestore', 'impala', ' enterprisedb', 'marketing']
    # for k in range(0,len(keywords)):
    #     keywords[k] = keywords[k].lower()

    # for w in s.split(" "):
    #     w=w.lower()
    #     x =w.upper()
    #     if w in keywords and w not in tags["tag"] and x not in tags["tag"]:
    #         w = w.upper()
    #         print(w)
    #         tags["tag"].append(w)
    #     if len(tags["tag"])==3:
    #         break 

    for k in tf_idf_score.keys():
        k = k.upper()
        k = k.replace(",","")
        if not(k.isnumeric()) and k not in tags["tag"] and k.upper() not in tags["tag"] :
            tags["tag"].append(k)
        
        if len(tags["tag"])==5:
            break

     

    #For sending tags to database
    print(tags)
    global taggs
    taggs = tags
    print("global",taggs)   
    global finaltags
    finaltags=taggs["tag"]
    print("Tags",tags)
    global uniqueId2
    conn=MongoClient()
    db=conn.Lucid
    collection=db.knowledge
    print(uniqueId2,finaltags, "uid h ye")
    db.knowledge.update({'ID':uniqueId2},{"$set": {'tags':finaltags}})

def contri_to_neo(ppdescription,ppsummary,pproducts, pkanalysis,pkinsisghts,powner,pptype, uniqueId2,finaltags,bugid):
    #global ppdescription,ppsummary,pproducts, pkanalysis,pkinsisghts,powner,pptype, uniqueId2,finaltags
    final_Tags=""
    for i in finaltags:
        final_Tags+=i+","  

    
    #added neo4j database
    # neo4j_create_statemenet = "create (a: Problem{name:'%s'}), (k:Owner {owner:'%s'}), (l:Problem_Type{type:'%s'}),(m:Problem_Summary{summary:'%s'}), (n:Probelm_Description{description:'%s'}),(o:Knowledge_Analysis{analysis:'%s'}), (p:Knowledge_Insights{kinsisghts:'%s'}), (a)-[:Owner]->(k), (a)-[:Problem_Type]->(l), (a)-[:Problem_Summary]->(m), (a)-[:Problem_Description]->(n), (a)-[:Knowledge_analysis]->(o), (a)-[:Knowledge_insights]->(p)"%("Problem",powner,pptype,ppsummary,ppdescription,pkanalysis,pkinsisghts)
    graphdb=GraphDatabase.driver(uri = "bolt://localhost:7687", auth=("neo4j", "admin"))
    session=graphdb.session()
    q2='''Merge (kp:knowledge {pdescription: '%s', ptype: '%s', psummary: '%s',id: '%s' , kanalysis:'%s', kinsisghts:'%s', owner:'%s', products:'%s',bugid:'%s'})
    WITH kp
    UNWIND split('%s',',') AS tag
    MERGE (t:final_Tags {tagname: tag})
    MERGE (kp)-[:belongs_to]->(t)'''%(ppdescription,pptype,ppsummary,uniqueId2,pkanalysis,pkinsisghts,powner,pproducts,bugid,final_Tags[:-1])
    q1=" match(n) return n "

    session.run(q2)
    session.run(q1)

def defects(request):
    conn = MongoClient()
    db=conn.Lucid
    collection=db.knowledge
    defectdata =collection.find({'ptype':'defect'})
    return render(request, 'knowledgepages/defects.html', {'defectdata': defectdata.clone()}) 

def defect(request):
    # conn = MongoClient()
    # db=conn.Lucid
    # collection=db.knowledge
    # defectdata =collection.find({'ptype':'defect'})
    graphdb=GraphDatabase.driver(uri = "bolt://localhost:7687", auth=("neo4j", "admin"))
    session=graphdb.session()
    q3="Match (t:Problem_Type)-[r:PROBLEM_DESCRIPTION]-> (c:Problem_Description) return t.ptype AS p_type,c.pdescription AS p_description"
    nodes=session.run(q3)
    return render(request, 'knowledgepages/defect.html', {'nodes': nodes}) 

def enhancements(request):
    conn = MongoClient()
    db=conn.Lucid
    collection=db.knowledge
    enhancementdata =collection.find({'ptype':'enhancement'})
    return render(request, 'knowledgepages/enhancements.html', {'enhancementdata': enhancementdata.clone()})

def supportticket(request):
    conn = MongoClient()
    db=conn.Lucid
    collection=db.knowledge
    supportdata =collection.find({'ptype':'support Ticket'})
    return render(request, 'knowledgepages/supportticket.html', {'supportdata': supportdata.clone()})

def opportunity(request):
    conn = MongoClient()
    db=conn.Lucid
    collection=db.knowledge
    opportunitydata =collection.find({'ptype':'opportunity'})
    return render(request, 'knowledgepages/opportunity.html', {'opportunitydata': opportunitydata.clone()})


global fname
def signin(request):       
    if request.method == 'POST':
        username = request.POST['username']
        pass1 = request.POST['pass1']
        global uName
        uName=username
        
    #below we are doing user authentication  
      
        user = authenticate(username=username, password=pass1)   
         
        if user is not None:
             login(request, user)
             fname = user.first_name
             global global_First_Name
             if '@' in fname:
                s=fname.split('@')
                global_First_Name=s[0].capitallize()
             else:
                global_First_Name=fname
             current_user = {}
             global username1
             username1=username
             datetime_login = datetime.datetime.now()
             global datetime_login1
             datetime_login1=datetime_login
             return render(request, "authentication/index.html", {'fname': fname})
             
        else:
            messages.error(request, "Bad Credentials!")
            return redirect('signin')
    
    
    return render(request, "authentication/signin.html")



def signout(request):
    logout(request)
    datetime_logout = datetime.datetime.now()
    global datetime_logout1
    datetime_logout1=datetime_logout
    messages.success(request, "Logged Out Successfully")
    return redirect('home')

def activate(request, uidb64, token):
    
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None
        
    if myuser is not None and generate_token.check_token(myuser, token):
        myuser.is_active = True
        myuser.save()
        login(request, myuser)
        return redirect('home')
    else:
        return render(request, 'activation_failed.html')

def freshdesk(request):
    conn = mod2.connect("Domain=knowledgeplatform640;  APIKey=VdMbeOevbxFSUFS5mYJd;")
    if request.method=="POST":
        Id=request.POST.get('tid')
        cmd = "SELECT Id, Subject, Description FROM Tickets where ID= ?"
        params = [Id]
        cur = conn.execute(cmd,params)
        rs = cur.fetchall()
        for row in rs:
            print(row)

        global d1
        d1 = {'Id':[], 'Summary':[], 'Description':[]}

        for t in rs:
            print("Hello")
            d1['Id'].append(t[0]);
            d1['Summary'].append(t[1]);
            d1['Description'].append(t[2]);
        print(d1)
        freshdeskdisplayss(d1)
        return render(request,'knowledgepages/freshdeskdisplay.html',context2)
    return render(request,'knowledgepages/freshdesk.html')

def freshdeskdisplayss(d1):
    ml=zip(d1['Id'],d1['Summary'],d1['Description'])
    global context2
    context2={'ml':ml,}

def freshdeskdisplay(request):
    return render(request,'knowledgepages/freshdeskdisplay.html',context)



def jira(request):
    conn = mod4.connect("User=knowledgeplatform64@gmail.com;APIToken=Ws7f12FDqg9MCO2WLDHw0AA2;Url=https://knowledgeplatform64.atlassian.net")
    # cur = conn.execute("SELECT Summary, Id, Description FROM Issues where id=10000")
    if request.method == 'POST':
        bug_id = request.POST['jiraid']
        aname = request.POST['aname']
        print(bug_id,aname)
        cmd = "SELECT Summary, Id, Description, AssigneeDisplayName FROM Issues WHERE Id = ? and AssigneeDisplayName=?"
        params = [bug_id, aname]
        cur = conn.execute(cmd, params)
        rs = cur.fetchall()
        for row in rs:
            print(row)


        global d
        d = {'Summary':[], 'BugId':[], 'Description':[], 'Assignee':[]}

        for t in rs:
            # print("Hello")
            d['Summary'].append(t[0]);
            d['BugId'].append(t[1]);
            d['Description'].append(t[2])
            d['Assignee'].append(t[3])
        print(d)
        jiradisplayss(d)
        return render(request,'knowledgepages/jiradisplay.html',context)

    return render(request,'knowledgepages/jira.html')


def jiradisplayss(d):
    ml=zip(d['Summary'],d['BugId'],d['Description'],d['Assignee'])
    global context
    context={'ml':ml,}


def jiradisplay(request):
    return render(request,'knowledgepages/jiradisplay.html',context)


#This function is to make the connection to salesforce by using cdata salesforce driver
def salesforce(request):
    conn = mod3.connect("User='af@gcet.com';Password='admin123';Security Token='G7wSptekqNONY1L3hBSs9T27';") #here we import salesforce by name of mod3
    cur = conn.execute("SELECT Name,BillingState, Id FROM Account")
    rs = cur.fetchall()
    print(rs)
    for row in rs:
        print(row)
    
    global d2
    d2 = {'name':[], 'billingState':[], 'id' : []}

    for t in rs:
        print("Hello")
        d2['name'].append(t[0]);
        d2['billingState'].append(t[1]);
        d2['id'].append(t[2])

    return render(request, 'knowledgepages/salesforce.html')          


#This function is used to display the tickets that are raised in salesforce
def salesforcedisplay(request):
    mlt=zip(d2['name'],d2['billingState'],d2['id'])
    context={'mlt':mlt,}
    return render(request, 'knowledgepages/salesforcedisplay.html',context)


#This function is used for full text search by using neo4j
def search(request):
    # conn = MongoClient()
    # db=conn.Lucid
    # collection=db.knowledge
    if request.method=="POST":
        searched=request.POST['searched']
    graphdb=GraphDatabase.driver(uri = "bolt://localhost:7687", auth=("neo4j", "admin")) #Connection to neo4j
    session=graphdb.session()
    q3='''CALL db.index.fulltext.queryNodes("kpindex", "%s") YIELD node RETURN node''' %(searched)   #This is fulltext search query
    nodes=session.run(q3) 
    # print(*nodes)
    # we are showing results on page name defect
    return render(request, 'knowledgepages/defect.html', {'nodes': nodes})

#This function render the user to the page where user can see the knowledges that are contributed by him
def your_Contribution(request):
    conn = MongoClient()
    db=conn.Lucid
    collection=db.knowledge    
    
    owner = gfName  #here gfName is global variable whose value is userfirstname
    print(owner)
    #login=Contribute.objects.filter(ptype__contains=searched) 
    defectdata =collection.find({'owner':owner})
    # return render(request, 'knowledgepages/defects.html', {'defectdata': defectdata.clone()}) 
    return render(request,'authentication/your_contribution.html',{'defectdata': defectdata.clone()})


def Zoho(request):
    mod1.connect("InitiateOAuth=GETANDREFRESH;") 
    return render(request, "authentication/zoho.html")   


#This function is used to update knowledge by taking knowledge ID from user
def update_contribution(request):
    conn=MongoClient()
    db=conn.Lucid
    collection=db.knowledge
    if request.method=="POST":
        kid=request.POST['kid']
        global uniqueId
        uniqueId=kid
    return render(request,'authentication/update_contribution.html')    

#This function render the user to the page where user can see knowledge for the particular knowledge ID he entered and have the option to update that knowledge
def update_contribution_display(request):
    global uniqueId
    print(uniqueId)
    conn = MongoClient()
    db=conn.Lucid
    collection=db.knowledge
    ourdata = collection.find({'ID':uniqueId})
    return render(request,'authentication/update_contribution_display.html',{'ourdata':ourdata.clone()})

#This function update the knowledge of the particular knowledge ID entered by the user
def update_data(request):
    global uniqueId
    # print("Inside update function",uniqueId)
    conn = MongoClient()
    db=conn.Lucid
    collection=db.knowledge
    udata=collection.find({'ID':uniqueId})
    d={'udata':udata.clone()}
    for x in d['udata']:
        p1=x['ptype']
        p2=x['psummary']
        p3=x['pdescription']
        p4=x['products']
        p5=x['kanalysis']
        p6=x['kinsisghts']
    if request.method=="POST":
        ptype=request.POST['ptype']
        # print(ptype,"ptype h ye")
        if(ptype=="Problem Type"):
            ptype=p1
        psummary=request.POST['psummary']
        if(psummary==""):
            psummary=p2
        pdescription=request.POST['pdescription']
        if(pdescription==""):
            pdescription=p3
        products=request.POST.getlist('CD')
        if(products==[]):
            products=p4
        kanalysis=request.POST['kanalysis']
        if(kanalysis==""):
            kanalysis=p5
        kinsisghts=request.POST['kinsisghts']
        if(kinsisghts==""):
            kinsisghts=p6

        db.knowledge.update({'ID':uniqueId},{'ID':uniqueId,'ptype':ptype,'psummary':psummary,'pdescription':pdescription,'products':products,'kanalysis':kanalysis,'kinsisghts':kinsisghts,'owner':gfName,'tags':finaltags})    #update this knowledge in MongoDb
        messages.success(request, "Data Updated Successfully")
        p2=""
        for i in products:
            p2+=i+","
        p2=p2[:-1]
        update_to_neo(pdescription,psummary,p2, kanalysis,kinsisghts,gfName,ptype, uniqueId) #update this knowledge in neo4j
    return render(request, "authentication/index.html")       

#This function is used to update data in neo4j when user update any knowledge
def update_to_neo(ppdescription,ppsummary,pproducts, pkanalysis,pkinsisghts,powner,pptype, uniqueId2):
    #global ppdescription,ppsummary,pproducts, pkanalysis,pkinsisghts,powner,pptype, uniqueId2,finaltags
    
    
    #added neo4j database
    # neo4j_create_statemenet = "create (a: Problem{name:'%s'}), (k:Owner {owner:'%s'}), (l:Problem_Type{type:'%s'}),(m:Problem_Summary{summary:'%s'}), (n:Probelm_Description{description:'%s'}),(o:Knowledge_Analysis{analysis:'%s'}), (p:Knowledge_Insights{kinsisghts:'%s'}), (a)-[:Owner]->(k), (a)-[:Problem_Type]->(l), (a)-[:Problem_Summary]->(m), (a)-[:Problem_Description]->(n), (a)-[:Knowledge_analysis]->(o), (a)-[:Knowledge_insights]->(p)"%("Problem",powner,pptype,ppsummary,ppdescription,pkanalysis,pkinsisghts)
    graphdb=GraphDatabase.driver(uri = "bolt://localhost:7687", auth=("neo4j", "admin"))
    session=graphdb.session()
    q3='''MATCH (p {id:'%s'})
    SET p = {id:'%s',owner: '%s', pdescription: '%s',
    ptype:'%s',kanalysis:'%s',kinsisghts:'%s',
    products: '%s',psummary:"%s"}''' %( uniqueId2,uniqueId2,powner,ppdescription,pptype,pkanalysis,pkinsisghts,pproducts,ppsummary)
        

    nodes=session.run(q3) 


#This function is used to delete any knowledge from Mongodb and neo4j by knowledge Id
def delete_data(request):
     global uniqueId
     conn = MongoClient()
     db=conn.Lucid
     collection=db.knowledge
     db.knowledge.remove({'ID':uniqueId})
     graphdb=GraphDatabase.driver(uri = "bolt://localhost:7687", auth=("neo4j", "admin"))
     session=graphdb.session()
     q33=''' MATCH (n {id:'%s'})
     DETACH DELETE n''' %(str(uniqueId))
     nodes=session.run(q33)
    
     messages.success(request, "Data Deleted Successfully")
     return render(request, "authentication/index.html")


rrrname="" #This variable stores the username when user clicks on forget password
#This function is used when user forget password, then this function take username and send email to user register emailid to authenticate user
def forget_password(request):
    if request.method=="POST":
        username=request.POST.get("username")
        global rrrname
        rrrname=username

        if not User.objects.filter(username=username):
            messages.success(request, "No user found")
            return redirect("home")
        
        else:
            user_obj=User.objects.get(username=username)
            current_site = get_current_site(request)
            email_subject = "Your forget Password link"
            message2 = render_to_string('authentication/change_password.html',{
            'name':user_obj.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user_obj.pk)),
            'token': generate_token.make_token(user_obj)
        })
            email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [user_obj.email],
        )
            email.fail_silently = True  #If email not sent then site will not crash
            email.content_subtype = "html" 
            email.send()
            messages.success(request, " We have sent link to your registered email for reset password.")

    return render(request,'authentication/forget_password.html')

#This function is used to activate link which comes on email id when user clicks on forget password button
def activate2(request, uidb64, token):
    
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None
        
    if myuser is not None and generate_token.check_token(myuser, token):
        myuser.is_active = True
        myuser.save()
        return render(request,'authentication/change_password_form.html')
    else:
        return render(request, 'activation_failed.html')


#This function is used when user wants to change Password of his account
def change_password_form(request):
    global rrrname #if user is not logged in, it takes username from forgetpassword
    global uName  #if user is logged in, it takes username from signin
    if(rrrname==""):
        rrrname=uName
    if request.method=="POST":
        pass1=request.POST.get('pass1') #To get new password
        pass2=request.POST.get('pass2') #To get again the same new password for authentication
        if(pass1!=pass2):
            messages.success(request,"Password not Matched")
            return render(request,"authentication/change_password_form.html")
        else:
            user_obj=User.objects.get(username=rrrname)  
            user_obj.set_password(pass1) #It sets the new password to pass1
            user_obj.save()
            messages.success(request,"Password changed Successfully")
            return render(request,"authentication/signin.html")
        
    return render(request,'authentication/change_password_form.html')


#This function is used to contribute knowledge by using Jira
def contribute_bug(request):
    global d
    psummary=d['Summary'][0]
    pdescription=d['Description'][0]
    bid=str(d['BugId'][0])
    if request.method == "POST":
        ptype=request.POST['ptype']
        products=request.POST.getlist('CD')
        kanalysis=request.POST['kanalysis']
        kinsisghts=request.POST['kinsisghts']
        owner=request.POST['owner']     
        generateTags(pdescription,psummary,kanalysis,kinsisghts,products)  
        p2=""
        for i in products:
            p2+=i+","
        p2=p2[:-1]
        
        conn = MongoClient()
        db=conn.Lucid
        collection=db.knowledge
        rec1={
                  
          "ptype":ptype,
          "psummary":psummary,
          "pdescription":pdescription,
          "products":products,
          "kanalysis":kanalysis,
          "kinsisghts":kinsisghts,
          "tags":finaltags,
          "owner":owner,
          "BugId":bid,
          "ID" : owner[:3] + str(len(psummary)) + str(len(pdescription)) +str(len(kinsisghts) + len(kanalysis)),                 
        }
        collection.insert_one(rec1)
        global uniqueId3
        uniqueId3=owner[:3] + str(len(psummary)) + str(len(pdescription)) +str(len(kinsisghts) + len(kanalysis))
        contri_to_neo(pdescription,psummary,p2, kanalysis,kinsisghts,owner,ptype,uniqueId3,finaltags,bid)
        messages.success(request, 'Your message has been sent!')
        return redirect('home')
    return render(request,'authentication/contribute_bug.html')


#This function is used to contribute knowledge by using freshdesk
def contribute_bug2(request):
    global d1
    psummary=d1['Summary'][0]
    pdescription=d1['Description'][0]
    bid=str(d1['Id'][0])
    if request.method == "POST":
        ptype=request.POST['ptype']
        products=request.POST.getlist('CD')
        kanalysis=request.POST['kanalysis']
        kinsisghts=request.POST['kinsisghts']
        owner=request.POST['owner']   
        generateTags(pdescription,psummary,kanalysis,kinsisghts,products)  
        
        p2=""
        for i in products:
            p2+=i+","
        p2=p2[:-1]
        contri_to_neo(pdescription,psummary,p2, kanalysis,kinsisghts,owner,ptype, uniqueId2,finaltags)
        
        conn = MongoClient()
        db=conn.Lucid
        collection=db.knowledge
        rec1={
                  
          "ptype":ptype,
          "psummary":psummary,
          "pdescription":pdescription,
          "products":products,
          "kanalysis":kanalysis,
          "kinsisghts":kinsisghts,
          "tags":finaltags,
          "owner":owner,
          "BugId":bid,
          "ID" : owner[:3] + str(len(psummary)) + str(len(pdescription)) +str(len(kinsisghts) + len(kanalysis)),                 
        }
        collection.insert_one(rec1)
        messages.success(request, 'Your message has been sent!')
        return redirect('home')
    return render(request,'authentication/contribute_bug2.html')


#This function is used to search knowledge by using tags
def searching2(request):
    return render(request,"authentication/searching2.html")