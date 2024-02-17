
import query.*;
import status.Event;
import status.Status;

import java.io.File;
import java.io.FileFilter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

public class LogParser implements IPQuery, UserQuery, DateQuery, EventQuery, QLQuery {

    private File[] logs;
    private final List<String> logData = new ArrayList<String>();
    private final List<LogEntry> logEntries = new ArrayList<LogEntry>();
    private final SimpleDateFormat sdf = new SimpleDateFormat("dd.MM.yyyy HH:mm:ss");

    public LogParser(Path logDir) {
        init(logDir);
    }

    private void init(Path logDir) {
        logs = new File(String.valueOf(logDir)).listFiles(new FileFilter() {
            @Override
            public boolean accept(File pathname) {
                return pathname.toString().endsWith(".log");
            }
        });
        parseLogs();
    }

    private void parseLogs() {
        for (File file : logs) {
            try {
                logData.addAll(Files.readAllLines(file.toPath(), StandardCharsets.UTF_8));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        logsToArray();
    }

    private void logsToArray() {
        for (String log : logData) {
            List<String> list = Arrays.asList(log.split("\t"));
            try {
                String ip = list.get(0).trim();
                String user = list.get(1).trim();
                Date date = sdf.parse(list.get(2));
                String[] eventStr = list.get(3).split(" ");
                Event event = Event.valueOf(eventStr[0]);
                int action = eventStr.length == 2 ? Integer.parseInt(eventStr[1]) : 0;
                Status status = Status.valueOf(list.get(4));
                LogEntry entry = new LogEntry(ip, user, date, event, action, status);
                logEntries.add(entry);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private boolean checkDate(Date current, Date after, Date before) {
        boolean isBefore = true;
        boolean isAfter = true;
        if (after != null && !current.after(after)) isAfter = false;
        if (before != null && !current.before(before)) isBefore = false;
        return isBefore && isAfter;
    }

    private Set<String> getUniqueIps(Date after, Date before) {
        HashSet<String> uniqueIPs = new HashSet<String>();
        for (LogEntry entry : logEntries) {
            if (checkDate(entry.getDate(), after, before)) {
                uniqueIPs.add(entry.getIp());
            }
        }
        return uniqueIPs;
    }

    @Override
    public int getNumberOfUniqueIPs(Date after, Date before) {
        return getUniqueIps(after, before).size();
    }

    @Override
    public Set<String> getUniqueIPs(Date after, Date before) {
        return getUniqueIps(after, before);
    }

    @Override
    public Set<String> getIPsForUser(String user, Date after, Date before) {
        HashSet<String> IPsForUser = new HashSet<String>();
        for (LogEntry entry : logEntries) {
            if (!entry.getUser().equals(user)) continue;
            if (checkDate(entry.getDate(), after, before)) {
                IPsForUser.add(entry.getIp());
            }
        }
        return IPsForUser;
    }

    @Override
    public Set<String> getIPsForEvent(Event event, Date after, Date before) {
        HashSet<String> IPsForEvent = new HashSet<String>();
        for (LogEntry entry : logEntries) {
            if (!entry.getEvent().equals(event)) continue;
            if (checkDate(entry.getDate(), after, before)) {
                IPsForEvent.add(entry.getIp());
            }
        }
        return IPsForEvent;
    }

    @Override
    public Set<String> getIPsForStatus(Status status, Date after, Date before) {
        HashSet<String> IPsForStatus = new HashSet<String>();
        for (LogEntry entry : logEntries) {
            if (!entry.getStatus().equals(status)) continue;
            if (checkDate(entry.getDate(), after, before)) {
                IPsForStatus.add(entry.getIp());
            }
        }
        return IPsForStatus;
    }

    @Override
    public Set<String> getAllUsers() {
        return logEntries.stream().map(LogEntry::getUser).collect(Collectors.toSet());
    }

    @Override
    public int getNumberOfUsers(Date after, Date before) {
        return logEntries.stream()
                .filter(e -> checkDate(e.getDate(), after, before))
                .map(LogEntry::getUser)
                .collect(Collectors.toSet()).size();
    }

    @Override
    public int getNumberOfUserEvents(String user, Date after, Date before) {
        return logEntries.stream()
                .filter(e -> checkDate(e.getDate(), after, before))
                .filter(e -> e.getUser().equals(user))
                .map(LogEntry::getEvent)
                .collect(Collectors.toSet()).size();
    }

    @Override
    public Set<String> getUsersForIP(String ip, Date after, Date before) {
        return logEntries.stream()
                .filter(e -> checkDate(e.getDate(), after, before))
                .filter(e -> e.getIp().equals(ip))
                .map(LogEntry::getUser).collect(Collectors.toSet());
    }

    @Override
    public Set<String> getLoggedUsers(Date after, Date before) {
        return logEntries.stream()
                .filter(e -> checkDate(e.getDate(), after, before))
                .filter(e -> e.getEvent().equals(Event.LOGIN))
                .map(LogEntry::getUser)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<String> getDownloadedPluginUsers(Date after, Date before) {
        return logEntries.stream()
                .filter(e -> checkDate(e.getDate(), after, before))
                .filter(e -> e.getEvent().equals(Event.DOWNLOAD))
                .map(LogEntry::getUser)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<String> getWroteMessageUsers(Date after, Date before) {
        return logEntries.stream()
                .filter(e -> checkDate(e.getDate(), after, before))
                .filter(e -> e.getEvent().equals(Event.WRITE_MESSAGE))
                .map(LogEntry::getUser)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<String> getSolvedTaskUsers(Date after, Date before) {
        return logEntries.stream()
                .filter(e -> checkDate(e.getDate(), after, before))
                .filter(e -> e.getEvent().equals(Event.SOLVE_TASK))
                .map(LogEntry::getUser)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<String> getSolvedTaskUsers(Date after, Date before, int task) {
        return logEntries.stream()
                .filter(e -> checkDate(e.getDate(), after, before))
                .filter(e -> e.getEvent().equals(Event.SOLVE_TASK))
                .filter(e -> e.getAction() == task)
                .map(LogEntry::getUser)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<String> getDoneTaskUsers(Date after, Date before) {
        return logEntries.stream()
                .filter(e -> checkDate(e.getDate(), after, before))
                .filter(e -> e.getEvent().equals(Event.DONE_TASK))
                .map(LogEntry::getUser)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<String> getDoneTaskUsers(Date after, Date before, int task) {
        return logEntries.stream()
                .filter(e -> checkDate(e.getDate(), after, before))
                .filter(e -> e.getEvent().equals(Event.DONE_TASK))
                .filter(e -> e.getAction() == task)
                .map(LogEntry::getUser)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<Date> getDatesForUserAndEvent(String user, Event event, Date after, Date before) {
        return logEntries.stream()
                .filter(e -> e.getUser().equals(user))
                .filter(e -> e.getEvent().equals(event))
                .map(LogEntry::getDate)
                .filter(date -> checkDate(date, after, before)).collect(Collectors.toSet());
    }

    @Override
    public Set<Date> getDatesWhenSomethingFailed(Date after, Date before) {
        return logEntries.stream()
                .filter(e -> checkDate(e.getDate(), after, before))
                .filter(e -> e.getStatus().equals(Status.FAILED))
                .map(LogEntry::getDate).collect(Collectors.toSet());
    }

    @Override
    public Set<Date> getDatesWhenErrorHappened(Date after, Date before) {
        return logEntries.stream()
                .filter(e -> checkDate(e.getDate(), after, before))
                .filter(e -> e.getStatus().equals(Status.ERROR))
                .map(LogEntry::getDate).collect(Collectors.toSet());
    }

    @Override
    public Date getDateWhenUserLoggedFirstTime(String user, Date after, Date before) {
        return logEntries.stream()
                .filter(e -> e.getUser().equals(user))
                .filter(e -> e.getEvent().equals(Event.LOGIN))
                .filter(e -> checkDate(e.getDate(), after, before))
                .map(LogEntry::getDate).sorted()
                .findFirst().orElse(null);
    }

    @Override
    public Date getDateWhenUserSolvedTask(String user, int task, Date after, Date before) {
        return logEntries.stream()
                .filter(e -> e.getUser().equals(user))
                .filter(e -> e.getAction() == task)
                .filter(e -> e.getEvent().equals(Event.SOLVE_TASK))
                .filter(e -> checkDate(e.getDate(), after, before))
                .map(LogEntry::getDate).sorted()
                .findFirst().orElse(null);
    }

    @Override
    public Date getDateWhenUserDoneTask(String user, int task, Date after, Date before) {
        return logEntries.stream()
                .filter(e -> e.getUser().equals(user))
                .filter(e -> e.getAction() == task)
                .filter(e -> e.getEvent().equals(Event.DONE_TASK))
                .filter(e -> checkDate(e.getDate(), after, before))
                .map(LogEntry::getDate).sorted()
                .findFirst().orElse(null);
    }

    @Override
    public Set<Date> getDatesWhenUserWroteMessage(String user, Date after, Date before) {
        return logEntries.stream()
                .filter(e -> e.getUser().equals(user))
                .filter(e -> checkDate(e.getDate(), after, before))
                .filter(e -> e.getEvent().equals(Event.WRITE_MESSAGE))
                .map(LogEntry::getDate).collect(Collectors.toSet());
    }

    @Override
    public Set<Date> getDatesWhenUserDownloadedPlugin(String user, Date after, Date before) {
        return logEntries.stream()
                .filter(e -> e.getUser().equals(user))
                .filter(e -> checkDate(e.getDate(), after, before))
                .filter(e -> e.getEvent().equals(Event.DOWNLOAD))
                .map(LogEntry::getDate).collect(Collectors.toSet());
    }

    @Override
    public int getNumberOfAllEvents(Date after, Date before) {
        return logEntries.stream()
                .filter(e -> checkDate(e.getDate(), after, before))
                .map(LogEntry::getEvent)
                .collect(Collectors.toSet()).size();
    }

    @Override
    public Set<Event> getAllEvents(Date after, Date before) {
        return logEntries.stream()
                .filter(e -> checkDate(e.getDate(), after, before))
                .map(LogEntry::getEvent)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<Event> getEventsForIP(String ip, Date after, Date before) {
        return logEntries.stream()
                .filter((e) -> checkDate(e.getDate(), after, before))
                .filter(e -> e.getIp().equals(ip))
                .map(LogEntry::getEvent)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<Event> getEventsForUser(String user, Date after, Date before) {
        return logEntries.stream()
                .filter((e) -> checkDate(e.getDate(), after, before))
                .filter(e -> e.getUser().equals(user))
                .map(LogEntry::getEvent)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<Event> getFailedEvents(Date after, Date before) {
        return logEntries.stream()
                .filter(e -> checkDate(e.getDate(), after, before))
                .filter(e -> e.getStatus().equals(Status.FAILED))
                .map(LogEntry::getEvent)
                .collect(Collectors.toSet());
    }

    @Override
    public Set<Event> getErrorEvents(Date after, Date before) {
        return logEntries.stream()
                .filter(e -> checkDate(e.getDate(), after, before))
                .filter(e -> e.getStatus().equals(Status.ERROR))
                .map(LogEntry::getEvent)
                .collect(Collectors.toSet());
    }

    @Override
    public int getNumberOfAttemptToSolveTask(int task, Date after, Date before) {
        return logEntries.stream()
                .filter(e -> checkDate(e.getDate(), after, before))
                .filter(e -> e.getAction() == task)
                .filter(e -> e.getEvent().equals(Event.SOLVE_TASK))
                .collect(Collectors.toList()).size();
    }

    @Override
    public int getNumberOfSuccessfulAttemptToSolveTask(int task, Date after, Date before) {
        return logEntries.stream()
                .filter(e -> checkDate(e.getDate(), after, before))
                .filter(e -> e.getAction() == task)
                .filter(e -> e.getEvent().equals(Event.DONE_TASK))
                .toList().size();
    }

    @Override
    public Map<Integer, Integer> getAllSolvedTasksAndTheirNumber(Date after, Date before) {
        return logEntries.stream()
                .filter(e -> checkDate(e.getDate(), after, before))
                .filter(e -> e.getEvent().equals(Event.SOLVE_TASK))
                .collect(Collectors.toMap(LogEntry::getAction, e -> 1, Integer::sum));
    }

    @Override
    public Map<Integer, Integer> getAllDoneTasksAndTheirNumber(Date after, Date before) {
        return logEntries.stream()
                .filter(e -> checkDate(e.getDate(), after, before))
                .filter(e -> e.getEvent().equals(Event.DONE_TASK))
                .collect(Collectors.toMap(LogEntry::getAction, e -> 1, Integer::sum));
    }

    public Set<Date> getAllDates() {
        return logEntries.stream().map(LogEntry::getDate).collect(Collectors.toSet());
    }

    public Set<Status> getAllStatus(Date after, Date before) {
        return logEntries.stream()
                .filter(e -> checkDate(e.getDate(), after, before))
                .map(LogEntry::getStatus).collect(Collectors.toSet());
    }

    private Set<Date> getAllDatesForIP(String ip, Date after, Date before) {
        return logEntries.stream()
                .filter(e -> e.getIp().equals(ip))
                .map(LogEntry::getDate)
                .filter(date -> checkDate(date, after, before))
                .collect(Collectors.toSet());
    }

    private Set<Status> getAllStatusForIP(String ip, Date after, Date before) {
        return logEntries.stream()
                .filter(e -> e.getIp().equals(ip))
                .filter(e -> checkDate(e.getDate(), after, before))
                .map(LogEntry::getStatus)
                .collect(Collectors.toSet());
    }

    private Set<Date> getDatesForUser(String user, Date after, Date before) {
        return logEntries.stream()
                .filter(e -> e.getUser().equals(user))
                .map(LogEntry::getDate)
                .filter(date -> checkDate(date, after, before))
                .collect(Collectors.toSet());
    }

    private Set<Status> getStatusForUser(String user, Date after, Date before) {
        return logEntries.stream()
                .filter(e -> e.getUser().equals(user))
                .filter(e -> checkDate(e.getDate(), after, before))
                .map(LogEntry::getStatus)
                .collect(Collectors.toSet());
    }

    private Set<String> getIpsForDate(Date date, Date after, Date before) {
        return logEntries.stream()
                .filter(e -> e.getDate().equals(date))
                .filter(e -> checkDate(e.getDate(), after, before))
                .map(LogEntry::getIp)
                .collect(Collectors.toSet());
    }

    private Set<Status> getAllStatusForEvent(Event event, Date after, Date before) {
        return logEntries.stream()
                .filter(e -> e.getEvent().equals(event))
                .filter(e -> checkDate(e.getDate(), after, before))
                .map(LogEntry::getStatus)
                .collect(Collectors.toSet());
    }

    private Set<String> getUsersForDate(Date date, Date after, Date before) {
        return logEntries.stream()
                .filter(e -> e.getDate().equals(date))
                .filter(e -> checkDate(e.getDate(), after, before))
                .map(LogEntry::getUser)
                .collect(Collectors.toSet());
    }

    private Set<String> getUsersForEvent(Event event, Date after, Date before) {
        return logEntries.stream()
                .filter(e -> checkDate(e.getDate(), after, before))
                .filter(e -> e.getEvent().equals(event))
                .map(LogEntry::getUser)
                .collect(Collectors.toSet());
    }

    private Set<String> getAllIPsForStatus(Status status, Date after, Date before) {
        return logEntries.stream()
                .filter(e -> e.getStatus().equals(status))
                .filter(e -> checkDate(e.getDate(), after, before))
                .map(LogEntry::getIp)
                .collect(Collectors.toSet());
    }

    private Set<String> getUsersForStatus(Status status, Date after, Date before) {
        return logEntries.stream()
                .filter(e -> e.getStatus().equals(status))
                .filter(e -> checkDate(e.getDate(), after, before))
                .map(LogEntry::getUser)
                .collect(Collectors.toSet());
    }

    private Set<Date> getDateForStatus(Status status, Date after, Date before) {
        return logEntries.stream()
                .filter(e -> e.getStatus().equals(status))
                .map(LogEntry::getDate)
                .filter(date -> checkDate(date, after, before))
                .collect(Collectors.toSet());
    }

    private Set<Event> getEventForStatus(Status status, Date after, Date before) {
        return logEntries.stream()
                .filter(e -> e.getStatus().equals(status))
                .filter(e -> checkDate(e.getDate(), after, before))
                .map(LogEntry::getEvent)
                .collect(Collectors.toSet());
    }

    private Set<Event> getEventsForDate(Date date, Date after, Date before) {
        return logEntries.stream()
                .filter(e -> e.getDate().equals(date))
                .filter(e -> checkDate(e.getDate(), after, before))
                .map(LogEntry::getEvent)
                .collect(Collectors.toSet());
    }

    private Set<Status> getStatusForDate(Date date, Date after, Date before) {
        return logEntries.stream()
                .filter(e -> e.getDate().equals(date))
                .filter(e -> checkDate(e.getDate(), after, before))
                .map(LogEntry::getStatus)
                .collect(Collectors.toSet());
    }

    private Set<Date> getDatesForEvent(Event event, Date after, Date before) {
        return logEntries.stream()
                .filter(e -> e.getEvent().equals(event))
                .map(LogEntry::getDate)
                .filter(date -> checkDate(date, after, before))
                .collect(Collectors.toSet());
    }

    @Override
    public Set<?> execute(String query) {
        List<String> list = new ArrayList<String>();
        String[] twoParts = query.split("=");
        if (twoParts.length == 1) {
            return switch (query) {
                case "get ip" -> getUniqueIPs(null, null);
                case "get user" -> getAllUsers();
                case "get date" -> getAllDates();
                case "get event" -> getAllEvents(null, null);
                case "get status" -> getAllStatus(null, null);
                default -> null;
            };
        }
        String[] first = twoParts[0].split(" ");
        for (String part : first) {
            if (!part.isEmpty()) list.add(part.trim());
        }

        list.add(twoParts[1].replaceAll("\"", "").trim());
        if (twoParts[1].contains("and date between")) {
            String dates = twoParts[1].split("and date between")[1];
            String[] datesParts = dates.split("and");
            for (String date : datesParts)
                list.add(date.replaceAll("\"", "").trim());
            list.set(4, list.get(4).split("and")[0].trim());
        }
        String[] queryParts = list.toArray(new String[0]);
        Date after = null;
        Date before = null;
        if (queryParts.length>5) {
           try {
               after = sdf.parse(queryParts[5]);
               before = sdf.parse(queryParts[6]);
           } catch (ParseException e) {
               System.out.println("error");
           }
        }
        switch (queryParts[3]) {
            case "ip":
                switch (queryParts[1]) {
                    case "user":
                        return getUsersForIP(queryParts[4], after, null);
                    case "date":
                        return getAllDatesForIP(queryParts[4], after, before);
                    case "event":
                        return getEventsForIP(queryParts[4], after, before);
                    case "status":
                        return getAllStatusForIP(queryParts[4], after, before);
                }
            case "user":
                switch (queryParts[1]) {
                    case "ip":
                        return getIPsForUser(queryParts[4], after, before);
                    case "date":
                        return getDatesForUser(queryParts[4], after, before);
                    case "event":
                        return getEventsForUser(queryParts[4], after, before);
                    case "status":
                        return getStatusForUser(queryParts[4], after, before);
                }
            case "date":
                Date date = null;
                try {
                    date = sdf.parse(queryParts[4]);
                } catch (ParseException e) {
                    System.out.println("error parsing date");
                }
                switch (queryParts[1]) {
                    case "ip":
                        return getIpsForDate(date, after, before);
                    case "user":
                        return getUsersForDate(date, after, before);
                    case "event":
                        return getEventsForDate(date, after, before);
                    case "status":
                        return getStatusForDate(date, after, before);
                }
            case "event":
                switch (queryParts[1]) {
                    case "ip":
                        return getIPsForEvent(Event.valueOf(queryParts[4]), after, before);
                    case "user":
                        return getUsersForEvent(Event.valueOf(queryParts[4]), after, before);
                    case "date":
                        return getDatesForEvent(Event.valueOf(queryParts[4]), after, before);
                    case "status":
                        return getAllStatusForEvent(Event.valueOf(queryParts[4]), after, before);
                }
            case "status":
                switch (queryParts[1]) {
                    case "ip":
                        return getAllIPsForStatus(Status.valueOf(queryParts[4]), after, before);
                    case "user":
                        return getUsersForStatus(Status.valueOf(queryParts[4]), after, before);
                    case "date":
                        return getDateForStatus(Status.valueOf(queryParts[4]), after, before);
                    case "event":
                        return getEventForStatus(Status.valueOf(queryParts[4]), after, before);
                }
            default:
                return null;
        }
    }

    private static class LogEntry {
        private final String ip;
        private final String user;
        private final Date date;
        private final Event event;
        private final int action;
        private final Status status;

        public LogEntry(String ip, String user, Date date, Event event, int action, Status status) {
            this.ip = ip;
            this.user = user;
            this.date = date;
            this.event = event;
            this.action = action;
            this.status = status;
        }

        public String getIp() {
            return ip;
        }

        public String getUser() {
            return user;
        }

        public Date getDate() {
            return date;
        }

        public Event getEvent() {
            return event;
        }

        public int getAction() {
            return action;
        }

        public Status getStatus() {
            return status;
        }
    }
}