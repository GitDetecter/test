from datetime import datetime, time

class Event:
    def __init__(self, data) -> None:
        self.data = data

    def getProperty(self, type: str) -> str:
        return self.data[type]
    
    def getNestedProperty(self, type: str, subtype: str) -> str:
        return self.data[type][subtype]

    def printWarningMessage(self, msg: str) -> str:
        ''' print a warning message to the cmd '''
        print(f"Suspicious behavior detected:")
        print(msg)
    
    def handle(self) -> None:
        ''' this function is override by child classes '''
        pass


class PushEvent(Event):
    def __init__(self, data) -> None:
        super().__init__(data)

    # override parent method
    def handle(self) -> None:
        ''' check for suspicious behavior '''
        ''' print a message if necessary '''
        pushTime = self.getNestedProperty('head_commit', 'timestamp')
        # if push time is between 14:00 and 16:00
        if self.suspiciousPushTime(pushTime):
            self.printWarningMessage(f"Push time is {pushTime}")


    def suspiciousPushTime(self, pushTime: str) -> bool:
        ''' return True iff push time is between 2PM and 4PM '''
        startTime = time(14, 0)     # build 14:00
        endTime = time(16, 0)       # build 16:00
        pushTime = datetime.fromisoformat(pushTime).time()

        return startTime <= pushTime <= endTime


class TeamEvent(Event):
    def __init__(self, data) -> None:
        super().__init__(data)

    # override parent method
    def handle(self) -> None:
        ''' check for suspicious behavior '''
        ''' print a message if necessary '''
        if self.getProperty('action') == 'created':
            teamName = self.getNestedProperty("team", "name")
            if self.suspiciousName(teamName):
                self.printWarningMessage(f"Prefix of team {teamName} is hacker")

    def suspiciousName(self, teamName) -> bool:
        ''' return True iff teamName prefix is hacker '''
        return len(teamName) > 5 and teamName[:6] == 'hacker'


class RepositoryEvent(Event):
    def __init__(self, data) -> None:
        super().__init__(data)

    #override parent method
    def handle(self) -> None:
        ''' check for suspicious behavior '''
        ''' print a message if necessary '''
        if self.getProperty('action') == 'deleted':
            createdAt = self.getNestedProperty("repository", "created_at")
            deletedAt = self.getNestedProperty("repository", "updated_at")
            if self.quicklyDeleted(createdAt, deletedAt):
                repositoryName = self.getNestedProperty("repository", "name")
                self.printWarningMessage(f"repository {repositoryName} deleted quickly")


    def quicklyDeleted(self, createdAt, deletedAt) -> bool:
        ''' return true iff repository deletion time is at most
            maxDifference seconds after creating time'''
        maxDifference = 600         # in seconds
        createdAt = datetime.strptime(createdAt, "%Y-%m-%dT%H:%M:%SZ")
        deletedAt = datetime.strptime(deletedAt, "%Y-%m-%dT%H:%M:%SZ")

        return (deletedAt - createdAt).total_seconds() <= maxDifference


def getEvent(event_type: str, data) -> Event:
    ''' get request event type and request body '''
    ''' return an Event object holding the data '''
    events = {"push": PushEvent, "team": TeamEvent, "repository": RepositoryEvent}
    if event_type in events:
        return events[event_type](data)
    return Event(data)
