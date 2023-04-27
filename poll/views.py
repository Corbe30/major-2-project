import pickle
import random
import socket
import tracemalloc
from django.shortcuts import render,redirect
from . import models
import math
from datetime import datetime
from django.contrib.admin.forms import AuthenticationForm
import time, datetime
from hashlib import sha512, sha256
from .resources import *
from .merkleTree import merkleTree
import uuid
from django.conf import settings

resultCalculated = False


def sendMessage(port, message, option):
    s = socket.socket()
    s.connect(('localhost', port))

    temp = [option, message]
    temp = pickle.dumps(temp)

    s.send(temp)

def receiveMessage(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', port))
    s.listen(3)
    addr = 0
    while True:
        if(addr == 0):
            c, addr = s.accept()
            data = (c.recv(4096))

        if(addr != 0):
            break
    
    data = pickle.loads(data)
    if(data[0] == 'blockchain&ledger'):
        return data[1]

def shareBlockchainLedger():
    blockchain = models.Block.objects.all()
    ledger = models.Vote.objects.all()
    event = models.Event.objects.all()
    sendMessage(1000, [blockchain, ledger, event], 'blockchain&ledger')

def receiveBlockchainLedger():
    [blockchain, ledger, event] = receiveMessage(1000)
    blockchain.objects.all().delete()
    models.Block.objects.all().delete()
    models.Event.objects.all().delete()
    models.Vote.objects.all().delete()

    blockchain.save()
    ledger.save()
    event.save()

def createEvent(request):
    if request.method == 'POST':
        publickey_n = request.POST.get('privateKey_n')
        publickey_d = request.POST.get('privateKey_d')
        voter = models.Car.objects.filter(public_key_n = publickey_n)[0]
        publickey_e = voter.public_key_e
        
        priv_key = {'n': int(publickey_n), 'd':int(publickey_d)}
        pub_key = {'n':int(publickey_n), 'e':int(publickey_e)}

        timestamp = datetime.datetime.now().timestamp()
        ballot = "{}|{}".format(vote, timestamp)
        h = int.from_bytes(sha512(ballot.encode()).digest(), byteorder='big')
        signature = pow(h, priv_key['d'], priv_key['n'])

        hfromSignature = pow(signature, pub_key['e'], pub_key['n'])

        if hfromSignature == h:
            eventName = request.POST.get("eventName")
            myEvent1 = models.Event(eventID=0,occurance="hasOccured",eventName=eventName,count=0.0, creator_public_key_n=publickey_n)
            myEvent2 = models.Event(eventID=1,occurance="hasNotOccured",eventName=eventName,count=0.0, creator_public_key_n=publickey_n)
            myEvent1.save()
            myEvent2.save()
            return redirect("login")
    
    else:
        return render(request, 'poll/createevent.html')


def home(request):
    return render(request, 'poll/home.html')

def vote(request):
    events = models.Event.objects.all()
    context = {'events': events}
    return render(request, 'poll/vote.html', context)

def login(request):
    if request.method == 'POST':
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            return redirect('vote')
    else:  
        form = AuthenticationForm()
    return render(request, 'poll/login.html/')


def createFromSmartContract(voter, isCreator):
    lenVoteList = len(models.Vote.objects.all())
    if (lenVoteList > 0):
        block_id = lenVoteList + 1
    else:
        block_id = 1

    new_vote = models.Vote(vote=2)
    new_vote.block_id = block_id
    new_vote.voter_public_key_n = voter.public_key_n
    new_vote.location = "28.629926810308053, 77.372044875702"
    new_vote.timestamp = datetime.datetime.now().timestamp()

    
    if(not isCreator):
        new_vote.transaction = (48.0/100) * voter.reputation
        voter.reputation = max(0.0, (148.0/100) * voter.reputation)
    else:
        new_vote.transaction = (55.0/100) * voter.reputation
        voter.reputation = max(0.0, (155.0/100) * voter.reputation)
    
    voter.save()
    new_vote.save()
    
    status = 'Reputation added successfully'
    generateBlock()


def create(request, pk):
    print(request.user)
    voter = models.Car.objects.filter(username=request.user.username)[0]

    prevTime = 0
    prevTimes = models.Vote.objects.filter(voter_public_key_n = voter.public_key_n).order_by('-timestamp')
    if(len(prevTimes) != 0):
        prevTime = prevTimes[0].timestamp
    timeElapsed = datetime.datetime.now().timestamp() - prevTime

    if request.method == 'POST' and timeElapsed > minTimeForVoting: # also add check for geolocation??
        vote = pk
        lenVoteList = len(models.Vote.objects.all())
        if (lenVoteList > 0):
            block_id = lenVoteList + 1
        else:
            block_id = 1

        priv_key = {'n': int(request.POST.get('privateKey_n')), 'd':int(request.POST.get('privateKey_d'))}
        pub_key = {'n':int(voter.public_key_n), 'e':int(voter.public_key_e)}

        # Create ballot as string vector
        timestamp = datetime.datetime.now().timestamp()
        ballot = "{}|{}".format(vote, timestamp)
        h = int.from_bytes(sha512(ballot.encode()).digest(), byteorder='big')
        signature = pow(h, priv_key['d'], priv_key['n'])

        hfromSignature = pow(signature, pub_key['e'], pub_key['n'])

        if(hfromSignature == h):
            new_vote = models.Vote(vote=pk)
            new_vote.block_id = block_id
            new_vote.voter_public_key_n = voter.public_key_n
            new_vote.timestamp = timestamp
            new_vote.location = "28.629926810308053, 77.372044875702"
            new_vote.transaction = (-10.0/100) * voter.reputation
            voter.reputation = max(0.0, (90.0/100) * voter.reputation)
            voter.save()

            new_vote.save()
            
            status = 'Ballot signed successfully'
            generateBlock()
            SmartContractForResult()
            
            error = False
        else:
            status = 'Authentication Error'
            error = True
        context = {
            'ballot': ballot,
            'signature': signature,
            'status': status,
            'error': error,
        }
        print(error)
        if not error:
            return render(request, 'poll/status.html', context)

    return render(request, 'poll/failure.html', context)

prev_hash = '0' * 64


def SmartContractForResult():
    noOfVotes = len(models.Vote.objects.all())
    if(noOfVotes % vehicleCap == 0):
        list_of_votes = models.Vote.objects.all().order_by('-timestamp')
        list_of_votes = list_of_votes[:vehicleCap]
        for vote in list_of_votes:
            event = models.Event.objects.filter(eventID=vote.vote)[0]
            voter = models.Car.objects.filter(public_key_n=vote.voter_public_key_n)[0]
            if(voter.reputation > 0.2):
                event.count += 1*voter.reputation
                event.save()
            
        verdict = models.Event.objects.order_by('count').reverse()[0]

        # filter votes for and against the poll
        for vote in list_of_votes:
            voters = models.Car.objects.filter(public_key_n=vote.voter_public_key_n)
            if(len(voters) != 0):
                voter = models.Car.objects.filter(public_key_n=vote.voter_public_key_n)[0]
                if(vote.vote == verdict.eventID):
                    if(voter.public_key_n == verdict.creator_public_key_n):
                        createFromSmartContract(voter, True)
                    else:
                        createFromSmartContract(voter, False)

# def SmartContractForResult():
#     noOfVotes = len(models.Vote.objects.all())
#     if(math.ceil(noOfVotes*(0.9)) > vehicleCap ):
#         list_of_votes = models.Vote.objects.all()
#         voter_list = []
#         voter_reputation = []
#         for vote in list_of_votes:
#             voter = models.Car.objects.filter(public_key_n=vote.voter_public_key_n)[0]
#             voter_list.append(voter)
#             voter_reputation.append(voter.reputation)
       
#         reputation_total = sum(voter_reputation)

#         selected_voters = []

#         while len(selected_voters) < vehicleCap:
#             rand = int(random.uniform(0, reputation_total))
#             rep_sum = 0.0
#             for i in range(len(voter_list)):
#                 rep_sum += voter_reputation[i]
#                 if rand < rep_sum:
#                     if voter_list[i] not in selected_voters:
#                         selected_voters.append(voter_list[i])  
#                     break
       
#         for voter in selected_voters:
#             vote = models.Vote.objects.filter(voter_public_key_n = vote.public_key_n)[0]
#             event = models.Event.objects.filter(eventID=vote.vote)[0]
#             event.count += 1
#             event.save()
           
#         verdict = models.Event.objects.order_by('-count')[0]

#         # filter votes for and against the poll
#         for vote in list_of_votes:
#             voters = models.Car.objects.filter(public_key_n=vote.voter_public_key_n)
#             if(len(voters) != 0):
#                 voter = models.Car.objects.filter(public_key_n=vote.voter_public_key_n)[0]
#                 if(vote.vote == verdict):
#                     voter.reputation += 0.05
#                 else:
#                     voter.reputation -= 0.1

#                 voter.reputation = max(0.1, voter.reputation)
#                 voter.reputation = min(1.0, voter.reputation)

#                 voter.save()


# CREATE BLOCK FOR EACH TRANSACTION
def generateBlock():
    tracemalloc.start()
    if (len(models.Vote.objects.all()) % 1 == 0):
        global prev_hash
        transactions = models.Vote.objects.order_by('block_id').reverse()
        transactions = list(transactions)[:1]
        block_id = transactions[0].block_id

        str_transactions = [str(x) for x in transactions]

        merkle_tree = merkleTree.merkleTree()
        merkle_tree.makeTreeFromArray(str_transactions)
        merkle_hash = merkle_tree.calculateMerkleRoot()

        nonce = 0
        timestamp = datetime.datetime.now().timestamp()

        while True:
            self_hash = sha256('{}{}{}{}'.format(prev_hash, merkle_hash, nonce, timestamp).encode()).hexdigest()
            if self_hash[0] == '0':
                break
            nonce += 1
        
        block = models.Block(id=block_id,prev_hash=prev_hash,self_hash=self_hash,merkle_hash=merkle_hash,nonce=nonce,timestamp=timestamp)
        prev_hash = self_hash
        block.save()
        print('Block {} has been mined'.format(block_id))
        print(tracemalloc.get_traced_memory())

def retDate(v):
    v.timestamp = datetime.datetime.fromtimestamp(v.timestamp)
    return v

# VERIFY WEBPAGE
def verify(request):
    if request.method == 'GET':
        verification = ''
        tampered_block_list = verifyVotes()
        votes = []
        if tampered_block_list:
            verification = 'Verification Failed. Following blocks have been tampered --> {}.\
                The authority will resolve the issue'.format(tampered_block_list)
            error = True
        else:
            verification = 'Verification successful. All votes are intact!'
            error = False
            votes = models.Vote.objects.order_by('timestamp')
            votes = [retDate(x) for x in votes]
            
        context = {'verification':verification, 'error':error, 'votes':votes}
        return render(request, 'poll/verification.html', context)

# RESULT PAGE LOGIC
def result(request):
    if request.method == "GET":
        voteVerification = verifyVotes()
        if len(voteVerification):
                return render(request, 'poll/verification.html', {'verification':"Verification failed.\
                Votes have been tampered in following blocks --> {}. The authority \
                    will resolve the issue".format(voteVerification), 'error':True})

        context = {"verdict":models.Event.objects.order_by('-count')[0]}
        return render(request, 'poll/results.html', context)

# VERIFY BLOCKCHAIN
def verifyVotes():
    block_count = models.Block.objects.count()
    tampered_block_list = []
    for i in range (1, block_count+1):
        try:
            block = models.Block.objects.get(id=i)
        except:
            return "tampered"
        transactions = models.Vote.objects.filter(block_id=i)
        str_transactions = [str(x) for x in transactions]

        merkle_tree = merkleTree.merkleTree()
        merkle_tree.makeTreeFromArray(str_transactions)
        merkle_tree.calculateMerkleRoot()

        if (block.merkle_hash == merkle_tree.getMerkleRoot()):
            continue
        else:
            print(block.merkle_hash)
            print(merkle_tree.getMerkleRoot())
            tampered_block_list.append(i)

    checkforLossAndDoubleVoting = verifyLossAndDoubleVoting()

    if(checkforLossAndDoubleVoting):
        return checkforLossAndDoubleVoting

    return tampered_block_list

# VERIFY LOSS & DOUBLE VOTING
def verifyLossAndDoubleVoting():
    votes = models.Vote.objects.all()
    lastVote = votes.order_by('-timestamp')[0]

    reputation = models.Car.objects.filter(public_key_n=lastVote.voter_public_key_n)[0].reputation
    if((((-1.0)*lastVote.transaction)/reputation)*100 < 11):
        return "user malicious"

    for vote in votes:
        if(vote.voter_public_key_n == lastVote.voter_public_key_n and vote.location == lastVote.location):
            if(lastVote.timestamp == vote.timestamp):
                continue
            if(lastVote.timestamp - vote.timestamp < minTimeForVoting):
                return "double voting found"
    
    return []