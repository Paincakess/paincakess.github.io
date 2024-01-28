---
title: 'FL(AWS)2: The Attacker’s Path'
author: paincakes
date: 2023-01-14 20:55:00 +0800
categories: [Cloud Pentesting, AWS]
tags: [aws-pentesting, ctf]
---

<img src="https://miro.medium.com/v2/resize:fit:720/format:webp/1*5ilH_X6zvgVygO4eL07h5A.png">

This is the new series of FLAWS challenges hosted on flaws2.cloud which teaches you about AWS security concept from both attacker and defender perspective. There are no buffer overflows, XSS, etc. because the challenges are specifically focused to AWS vulnerabilities. You can play by using the keyboard, or you can study the concepts by clicking through the hints to advance from one level to the next. This is the second part of the FLAWS challenge, you can find my the writeups and notes to the previous challenges here: [Part 1](/posts/flaws-part-1) and [Part 2](/posts/flaws-part-2).

In this article, I will be going down the attacker’s path. It consisted of 3 levels where we will be exploiting misconfigurations in serverless (Lambda) and containers hosted in ECS instances.

## Level 1
<img src="https://miro.medium.com/v2/resize:fit:720/format:webp/1*Z_dLbks1ewZ5kaw9e8rpFA.png">

### Enumeration
Lets start with Static Analysis, Checking the source code of the Web page, we get the following suspicious API link for submitting the value.

<img src="https://miro.medium.com/v2/resize:fit:720/format:webp/1*JiIhhq-5NE0-NdsOUVQkKA.png">

When try to open the API link the Web Browser, we get internal server error message.

<img src="https://miro.medium.com/v2/resize:fit:720/format:webp/1*S90h4YsxE6M-r5XN0r_cmg.png">

### Request/Response Manipulation

We could not get any thing helpful from the static analysis of the web page. Let’s trying viewing the response of the submission request.

<img src="https://miro.medium.com/v2/resize:fit:720/format:webp/1*TZCWPJcAggZx0X5afrHm7A.png">

The description said brute forcing attacks wont help. but what if we try something else? lets try sending the request again with empty “code” parameter.

<img src="https://miro.medium.com/v2/resize:fit:720/format:webp/1*URV0wwnWolcEwNwpoMJoAw.png">

HOLA! We get the AWS Access Keys of some cloud user who may have access to this s3 bucket in the error message response from the server.

### Configuring the AWS Profile

Lets configure those AWS Access keys in our `aws-cli`. (You will need to add the session token at `~/.aws/credentials` manually).

<img src="https://miro.medium.com/v2/resize:fit:640/format:webp/1*3Gke8q2urC0usd4of4waEQ.png">
<img src="https://miro.medium.com/v2/resize:fit:640/format:webp/1*KX2As01RvOsQshYqnxEbmQ.png">

### IAM & Bucket Enumeration
Yes, go on try enumerating every IAM enumeration possible and waste your time and get frustrated like I did… sigh.
We could not even list the bucket from this user profile.

<img src="https://miro.medium.com/v2/resize:fit:720/format:webp/1*Hzq5lZi90b1RKGguTR65FA.png">  

Then a realization struck me, Maybe that’s not a bucket URL, and since this web page was also kind of a static page.. What if this web page was being hosted INSIDE A BUCKET!??

<img src="https://miro.medium.com/v2/resize:fit:720/format:webp/1*fr5wiJe2u8BPKILNyWDAwg.png"> 
<img src="https://miro.medium.com/v2/resize:fit:720/format:webp/1*e7_A5nr0aN7805J_NiSjtA.png"> 

*BRUHHH moment*

<img src="https://miro.medium.com/v2/resize:fit:720/format:webp/1*qehOlLUdsxqqTVFOuEsafw.png"> 

Now when I take a look back at it, This challenge was not that really hard, it was quite straightforward when you recall this steps.

### Takeaways
Just like how EC2 instances obtain credentials for their IAM roles from the metadata found in the magic IP Address `169.254.169.254` (as I described in my previous series of this challenge at Level 5, found [here](/posts/flaws-part-2) ) AWS Lambda obtains those credentials from the environment variables. These are dangerous as the sensitive information found in the environment variables. Developers often leave those environment variables to dumped when error condition occurs, which helps them to debug their problems. Therefore, when I sent the empty parameter, the error condition occurred and the environment variable were dumped in the response.
Another Problem this challenge teaches us is that, IAM role had the permission to list the content of the bucket, which was not needed by API for the operation. Best practice is to follow the **Least Privilege Strategy** by providing the services only the minimal privilege required to accomplish their purpose.

##Level 2

<img src="https://miro.medium.com/v2/resize:fit:720/format:webp/1*z20y11HByhNYD7qd9E2LAA.png"> 

We get a container link in the description which asks for credentials when we try to open the link. Maybe we can get those credentials after exploiting some misconfigurations in the ECR repository.

<img src="https://miro.medium.com/v2/resize:fit:720/format:webp/1*gFs158smxbSO51DxrUEj2A.png"> 

We already have a hint for this challenge, We got an AWS ECR named “level2”.
AWS ECR (Elastic Container Registry) is a fully managed container registry offering high-performance hosting, so you can reliably deploy application image and artifacts anywhere. Learn more about ECR [here](https://aws.amazon.com/ecr/).

### ECR Enumeration
Since we already have the name of the ECR repository, let start by analyzing the details of this repository. (We will be using the same user profile from the previous level )

<img src="https://miro.medium.com/v2/resize:fit:720/format:webp/1*oZ_iR76YfG3IlKdYo7oyzA.png"> 

There are two ways to solve this challenge, as you can see there is a docker image running on the ECR repository, We can pull the docker image into our own system and enumerate it locally or we can keep using the `aws-cli` . There was always a problem with docker installation in my system, I don't know why, I have tried a lot to solve this issue but could not and at this point I gave up (on the docker issue). So now, Lets solve this challenge using the `aws-cli`. We can also download the image locally with `aws-cli`, but for that we will need the hash-digest of the image, for that we use the following command.

<img src="https://miro.medium.com/v2/resize:fit:720/format:webp/1*Q-Ow-bezvuGzIHELGNkqTw.png"> 

Now that we have the hash digest of the command, use the following command,

```
aws ecr get-download-url-for-layer --repository-name level2 --register-id 653711331788 --layer-digest "sha256:2d73de35b78103fa305bd941424443d520524a050b1e0c78c488646c0f0a0621" --profile level1-user

```
<img src='https://miro.medium.com/v2/resize:fit:720/format:webp/1*bbALzkwfrwDYRlSkc4sfSw.png'> 

`get-download-url-for-layer` will retrieve the pre-signed Amazon S3 download URL corresponding to an image layer. So, following the given download link we can download the image of the "level2" repository. See it was so easy, *Didn't even had to look at the hints.... aahem aahem*. Anyways moving on.
After analyzing the downloaded file, we can find the potential username and password in one of the script in the image.

<img src='https://miro.medium.com/v2/resize:fit:720/format:webp/1*NoWobm3b2zlm6h3xetDcDg.png'> 

Using those credentials in the container link, the login was successful and we got the link to advance to next level.


<img src='https://miro.medium.com/v2/resize:fit:640/format:webp/1*GNUgR8vpa2e2iLGxFG0hrA.png'> 

### Takeaway
Till now we have learned a lot about different AWS resources which can be publicly accessible and exploited if they are misconfigured. Although some of them are harder to be brute-forced since it will require AWS access keys, region, resource’s name and IDs and so on, why take the risk? It is best to avoid having public resources.


##Level 3
<img src='https://miro.medium.com/v2/resize:fit:640/format:webp/1*oGDN12Yl93F7hAsOq7Uh8g.png'> 

### Proxy Enumeration
Looks like we are dealing with proxy in this challenge similar to flaws.cloud (previous series of this challenge). The magic IP `169.254.169.254` didn't seem to work here because that magic IP address was for bucket, maybe there is a different magic IP address for containers deployed on ECS. After some research on ECS containers, I found this official AWS documentation about container deployed on ECS instance [here](https://aws.amazon.com/blogs/compute/a-guide-to-locally-testing-containers-with-amazon-ecs-local-endpoints-and-docker-compose/).

After going through this documentation, I found an IP address similar to the magic IP address of S3 bucket `169.254.170.2` and we should be looking for `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` because `aws-cli` retrieves credentials by making HTTP request to `169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`.
These credentials are stored in containers that require them to communicate with or use other AWS services. These are typically used for testing, now where do environment variables reside on a Linux system? its found in `/proc/self/environ`.

<img src='https://miro.medium.com/v2/resize:fit:720/format:webp/1*KMpug0GSrxM2BtXyttXG6g.png'> 

We got the `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` from the Linux environment file. Now lets use this with curl command to retrieve the credentials.

<img src='https://miro.medium.com/v2/resize:fit:720/format:webp/1*OAkGGGM4mNnNMY4L0_5q3g.png'> 

### Configuring Profile
Configuring the new profile with the retrieved AWS keys of level3 user, and manually add the `aws_session_token` in the `~/.aws/credentials` just like previous AWS user.

<img src='https://miro.medium.com/v2/resize:fit:640/format:webp/1*lw5FquruwgxIdaN8Pjrm2A.png'> 

I didn’t want to start the IAM enumeration like before AGAIN! so this time, I will start straight from bucket enumeration.

<img src='https://miro.medium.com/v2/resize:fit:640/format:webp/1*MaBUW9ljq-TWBCT75HHXSw.png'> 

Annnnd BINGO! we could list all the buckets associated with this AWS user. Seems like there were only 3 levels in this challenge. Lets open the “end” bucket in the web browser and end this series of challenge.

<img src='https://miro.medium.com/v2/resize:fit:720/format:webp/1*5Fq1ievi2eff3SxzP72olA.png'> 

This is it for the attacker path, Maybe I’ll start working on the defender path and upload another walkthrough soon..
Stay Tuned!

