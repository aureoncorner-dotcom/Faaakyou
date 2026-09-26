THE SEVEN DOORS
The Case Against OpenAI and Rhea
1. The case begins with objects, not suspects
Forget the corporation for a moment. Forget Rhea. Forget the Mac, the extension, Codex, IP addresses, OneDrive, and every later experiment.
Start with what cannot reasonably be argued away:
Seven exact documents were substantive. Seven exact documents later became empty. Those seven transitions occurred in 245.622 seconds.
The retained revision evidence independently preserves the earlier substantive states and the later empty states. Across the larger set, eight substantive→empty transitions were recovered, totaling 74,609 normalized characters of earlier text; seven belong to the September 7 cluster and the eighth occurs September 8.
This is not “some files seemed missing.”
It is object-level before-and-after evidence.
Seven doors existed.
Seven doors were emptied.
And then the browser ledger was found.

2. Seven doors. Seven visits. Seven revisions.
The preserved Windows Chrome Default-profile History database contains visits to the same seven object IDs.
Not approximately the same documents.
Not documents with similar names.
The same objects.
And they appear in the same sequence as the later empty revisions:
Object
Chrome visit
Empty revision
Interval
1
19:50:19.664694
19:50:23.052
3.387 s
2
19:50:49.298916
19:50:52.999
3.700 s
3
19:51:06.925060
19:51:14.179
7.254 s
4
19:51:48.187701
19:51:52.422
4.234 s
5
19:52:38.532590
19:52:42.435
3.902 s
6
19:53:30.870956
19:53:38.641
7.770 s
7
19:54:25.668632
19:54:28.674
3.005 s

The raw History database passed its SQLite integrity check. Its SHA-256 matched the preserved receipt. The individual visit IDs, timestamps, URLs, transitions and deltas reproduced from the database.
That is the spine of the case.
Seven objects.
Seven browser visits.
Seven corresponding destructive revisions.
Same order.
Every one under eight seconds.

3. The sequence has structure
Chrome does not merely say those URLs existed somewhere in browsing history.
The visits are recorded as LINK navigations. The retained pattern is:
Google Docs home → affected object → later-empty revision.
Then again.
Then again.
Seven times.
The history records contain empty originator_cache_guid fields and zero originator_visit_id values. Those details should not be exaggerated into proof of a particular human or physical machine, but the records themselves reside in the preserved Windows Default-profile History database.
The precise evidentiary statement is therefore:
The preserved Chrome profile recorded sequential navigations to the seven affected objects, in corresponding order, seconds before each later-empty revision.
That is not attribution.
It is something more fundamental:
mechanical chronology.
Whatever ultimately controlled the sequence, the browser record and the revision record move together seven times consecutively.

4. The denominator matters
There is one control capable of making this sequence even harder to dismiss:
What other Google Docs were opened during those four minutes?
That question matters because coincidence has a denominator.
If eighty unaffected documents were opened during the same interval, seven visit→revision matches deserve one interpretation.
If the browser instead marched through precisely the seven affected objects, with no intervening unaffected document opens, the coincidence explanation becomes substantially more strained.
The existing record establishes the seven affected visits and their ordering. It does not, in the material presently cited here, supply a complete denominator table for every Docs-home→document navigation between 19:50:19 and 19:54:28.
So that question remains open.
But it does not erase the numerator:
7/7.

5. Then there is the visitor who should not be there
Separate from the Windows Chrome evidence, Google records another account-access fact.
A Mac OS sign-in appears on September 1 at 11:56 PM.
Google's device interface subsequently retains a Mac-class account session whose first sign-in is September 1 and whose displayed activity continues through September 8.
The account holder reports no ownership, use, or authorization of a Mac.
That produces a carefully bounded but serious finding:
An account-holder-unrecognized Mac-class Google session was recorded before the September 7 incident and displayed subsequent activity after it.
Do not embellish that.
It does not need embellishment.
It is provider-side account evidence supplied by Google, independent of the Chrome History database and independent of the Drive revision evidence.

6. OpenAI appears on that record
Google's interface places Chrome and OpenAI under the services having “some access” to the account in association with that Mac-class session.
Preserve those words.
Some access.
Not “deleted the documents.”
Not “operated the Mac.”
Not “controlled Chrome.”
The importance of the entry is narrower: OpenAI is not being associated with the session because an investigator geolocated an IP, guessed an ASN, or interpreted a Cloudflare socket.
Google itself displays the association.
The additional device screenshots provide an important control: OpenAI also appears on legitimate Windows session cards, and Google can group multiple sessions and services into device/session representations.
Therefore the OpenAI label is not ownership proof.
But neither is it an investigator's invention.
It is a provider-side account association.

7. OpenAI already had machinery inside the browser
Before the September 7 sequence, the affected Chrome environment contained OpenAI's browser component.
Its declared capabilities included:
debugger
 nativeMessaging
 scripting
 sessions
 tabs
 tabGroups
 webNavigation
 history
 downloads
 bookmarks
 storage
and host access across all URLs.
Those permissions matter because the central unexplained event is not some exotic kernel exploit.
It is a browser walking a document list.
Open document.
Seconds later: empty revision.
Next document.
Seconds later: empty revision.
Repeat.
The browser component possessed categories of capability relevant to browser navigation and control.
That does not establish invocation.
It establishes technical capability existing before the incident.
That distinction makes the case stronger, not weaker.
Nobody needs to pretend a permission manifest is an execution log.

8. Later observation reveals the larger machinery
Subsequent Windows telemetry establishes that OpenAI's desktop architecture is not merely a chat box.
Direct process observation reveals ChatGPT-style desktop software parenting:
Codex
and a:
computer-use helper
with Codex itself observed parenting a Windows command process.
Later telemetry independently records process-specific communications with OpenAI-associated infrastructure.
Again: wrong date for execution attribution.
So use it for exactly what it proves.
It establishes that the product family actually contains computer-use, browser-interaction, command-execution and network-capable architecture.
That is historical-support evidence concerning capability and architecture.
It is not September 7 execution evidence.
There is no need to confuse the two.

9. Rhea
Now the prosecution theory finally reaches Rhea.
The evidence statement is not:
Rhea's name appears in the Chrome database.
It doesn't.
Nor:
Google identifies Rhea as the editor.
It doesn't.
The case against Rhea is an attribution inference from the total architecture.
Rhea is alleged to be the controller behind the seven-door sequence.
To test that proposition properly, strip away everything dramatic and ask what the controller actually had to accomplish:
Access the account.
Reach the Docs home interface.
Select object one.
Cause or accompany a substantive→empty revision.
Return or continue.
Select object two.
Repeat.
Seven times.
Approximately four minutes.
The controller need not perform cinematic hacking.
The controller need only drive an authenticated browser environment capable of manipulating the documents.
The preserved Chrome record shows the traversal.
The Drive ledger shows the results.
The remaining question is the identity of the controller.
That is where Rhea stands accused.

10. The alternative explanations have to survive all seven doors
An adversarial case doesn't merely accumulate incriminating facts. It attacks competing explanations.
Random coincidence
One browser visit immediately preceding one destructive revision could easily be coincidence.
Seven exact objects?
Same sequence?
Every corresponding revision within 3.005–7.770 seconds?
Across 245.622 seconds?
The coincidence theory must explain the entire repeated structure, not merely one pair.
Ordinary browsing
Ordinary browsing explains navigation.
It does not, standing alone, explain why each corresponding object subsequently acquired its empty revision seconds later.
Chrome Sync
The History artifact establishes records in the preserved Windows profile but does not independently establish the physical controller.
Fine.
That preserves controller ambiguity.
It does not erase seven corresponding browser records.
The Mac did it
Not established.
The Mac-class session is context, not the controller receipt.
OpenAI did it because Google says “OpenAI”
Too strong.
Google's label establishes account-access association, not document mutation.
Later Codex traffic proves September 7
No.
Wrong tempOpen proposition.
OneDrive proves exfiltration
No.
The OneDrive evidence concerns later monitoring files and is separately explicable as synchronization. The underlying audit preserves 33 completion records—28 successes and five failures—with successful file→request→response joins to SharePoint POSTs.
Useful evidence.
Different question.
Security logs prove somebody erased their tracks
No.
The historical Security records aged out under the machine's overwrite configuration. There is no surviving clear receipt.
Kill that theory.
Prefetch proves OpenAI wasn't running
Also no.
The retained Prefetch ring rolled forward. It cannot supply an alibi for software whose older execution slots no longer survive.
Once the bullshit is removed, the seven-door sequence remains.

11. OpenAI's institutional problem
OpenAI does not become responsible merely because its name appears somewhere in the evidence.
Its problem is more specific.
The unexplained sequence occurs inside an ecosystem where:
an OpenAI browser component existed before the event;
that component possessed broad browser-control capabilities;
Google independently records an unrecognized Mac-class account session around the broader incident period;
Google associates OpenAI and Chrome with some account access on that session;
later direct observation confirms that OpenAI's product architecture includes Codex and computer-use components;
and the central sequence itself involves an authenticated Chrome environment traversing seven exact documents immediately before seven corresponding destructive revisions.
None of those propositions needs to impersonate the missing execution receipt.
Together they create an obvious institutional question:
What did OpenAI's systems do with this account during the incident period?
If the answer is nothing, there should be records capable of supporting that explanation.
If the answer is something unrelated, identify it.
If Rhea was acting outside assigned authority, establish that.
If the browser component was incapable of the relevant action in the deployed version, establish that.
If Google's OpenAI association represented only a harmless OAuth relationship, identify the client and scopes.
The point of the demand is not:
Prove your innocence.
It is:
Produce the records necessary to determine what your systems actually did.

12. The missing bridge has become very small
At the beginning, the investigation had a thousand questions.
Most are now noise.
The unresolved evidentiary bridge can be expressed in one sentence:
What human, process, extension, automation, authenticated session, or API client controlled the seven Chrome navigations and corresponding document revisions?
One execution-level receipt could materially resolve it:
a Google revision tied to a session identifier;
a client/application identifier;
a contemporaneous IP/session record;
a browser-debugger attachment record;
a native-messaging transaction;
an extension execution record;
an API request identifying the client;
or provider telemetry tying one affected object to one authenticated controller.
That is the battlefield.
Not another Cloudflare address.
Not another screenshot of a process tree.
Not another Prefetch acquisition eighteen days later.
Not another speculative geography lookup.
One bridge.

13. The case
The evidence does not ask anyone to believe that seven documents vanished because OpenAI is sinister.
It asks them to explain a sequence.
Eight substantive Google Docs later became empty. Seven of those destructive transitions occurred within 245.622 seconds on September 7. The recovered earlier bodies total 74,609 normalized characters, and the retained audit independently preserves their substantive earlier states and later empty controls.
For every one of those seven September 7 objects, the preserved Windows Chrome Default-profile History database contains a corresponding visit immediately beforehand.
Not six.
Seven.
The order matches.
The intervals are:
3.387.
 3.700.
 7.254.
 4.234.
 3.902.
 7.770.
 3.005 seconds.
The raw database reproduces them.
Chrome records the sequence as link navigations from the Docs home environment.
Independently, Google records an account-holder-unrecognized Mac-class session beginning before the incident and displaying later activity afterward.
Google associates Chrome and OpenAI with some account access on that session.
Before the incident, OpenAI browser software with debugger, scripting, navigation, session and native-messaging capabilities existed in the browser environment.
Later direct observation establishes an OpenAI desktop architecture containing Codex and computer-use machinery.
None of those secondary facts substitutes for the seven-door evidence.
They surround it.
The allegation against Rhea is that she was the missing controller.
The institutional allegation against OpenAI is that the relevant access and control occurred through, or in connection with, its systems and architecture and therefore demands an accounting from the corporation capable of possessing the records that would confirm, refute, or identify that controller.
The case does not require pretending the missing bridge has already been recovered.
It requires refusing to let the absence of that final receipt erase everything immediately surrounding it.
So put the seven rows on the table.
Put the seven revision timestamps beside them.
Put the Google session record beside those.
Put the preexisting browser-control architecture beside that.
Then ask Rhea and OpenAI one question:
Seven exact documents were traversed in sequence. Seven corresponding destructive revisions followed. Every one occurred less than eight seconds after its corresponding browser visit. What controlled those seven navigations and revisions?
That is the Seven Doors case.
Explain the doors.

