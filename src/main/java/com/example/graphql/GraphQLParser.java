package com.example.graphql;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Bộ phân tích cú pháp GraphQL "nhẹ" và khoan dung (lenient), viết thuần Java, không phụ thuộc
 * thư viện ngoài.
 * <p>
 * Mục tiêu KHÔNG phải là validate schema mà là bóc tách đủ thông tin để theo dõi tiến độ scan:
 * <ol>
 *     <li>Loại operation (query/mutation/subscription) và tên operation.</li>
 *     <li>Danh sách các root field của operation (đã "flatten" cả fragment spread ở mức root).</li>
 *     <li>Với mỗi root field: tập hợp tên tất cả argument xuất hiện trong toàn bộ cây con của nó
 *     (bao gồm argument lồng nhau và argument nằm trong fragment được tham chiếu).</li>
 * </ol>
 * Parser được thiết kế để "không ngã" trước các query bị Burp Scanner biến đổi giá trị: nó bỏ qua
 * mọi token không hiểu và luôn cố gắng trả về nhiều nhất có thể.
 */
public final class GraphQLParser {

    private GraphQLParser() {
    }

    /**
     * Phân tích một chuỗi query GraphQL thành danh sách các {@link GraphQLOperation}.
     * Mỗi root field của mỗi operation trở thành một phần tử trong danh sách.
     *
     * @param query chuỗi query/mutation thô.
     * @return danh sách operation (có thể rỗng nếu không parse được gì).
     */
    public static List<GraphQLOperation> parse(String query) {
        List<GraphQLOperation> result = new ArrayList<>();
        if (query == null || query.isBlank()) {
            return result;
        }

        List<String> tokens;
        try {
            tokens = tokenize(query);
        } catch (RuntimeException e) {
            return result;
        }
        if (tokens.isEmpty()) {
            return result;
        }

        Document document;
        try {
            document = new Parser(tokens).parseDocument();
        } catch (RuntimeException e) {
            return result;
        }

        for (Operation operation : document.operations) {
            // Gom theo TÊN root field: nhiều alias của cùng một field (hoặc field lặp qua fragment)
            // sẽ được hợp nhất argument để không bỏ sót injection point nào.
            Map<String, Set<String>> rootFieldArgs = new LinkedHashMap<>();
            collectRootFieldArgs(operation.selectionSet, document.fragments, new HashSet<>(), rootFieldArgs);
            for (Map.Entry<String, Set<String>> entry : rootFieldArgs.entrySet()) {
                result.add(new GraphQLOperation(operation.type, operation.name, entry.getKey(), entry.getValue()));
            }
        }
        return result;
    }

    // ===================================================================================
    // TOKENIZER
    // ===================================================================================

    /**
     * Chuyển chuỗi nguồn thành danh sách token. Chuỗi ký tự (string literal), block string,
     * comment (#...) và dấu phẩy được loại bỏ. Mọi string literal được thay bằng token
     * placeholder {@code "\"\""} để không phá vỡ việc đếm ngoặc.
     */
    static List<String> tokenize(String src) {
        List<String> tokens = new ArrayList<>();
        int i = 0;
        int n = src.length();
        while (i < n) {
            char c = src.charAt(i);

            if (Character.isWhitespace(c) || c == ',') {
                i++;
                continue;
            }

            // Comment tới hết dòng.
            if (c == '#') {
                while (i < n && src.charAt(i) != '\n') {
                    i++;
                }
                continue;
            }

            // Chuỗi ký tự.
            if (c == '"') {
                boolean block = i + 2 < n && src.charAt(i + 1) == '"' && src.charAt(i + 2) == '"';
                if (block) {
                    i += 3;
                    while (i + 2 < n && !(src.charAt(i) == '"' && src.charAt(i + 1) == '"' && src.charAt(i + 2) == '"')) {
                        if (src.charAt(i) == '\\') {
                            i++; // bỏ qua ký tự escape.
                        }
                        i++;
                    }
                    i += 3;
                } else {
                    i++; // bỏ dấu " mở.
                    while (i < n && src.charAt(i) != '"') {
                        if (src.charAt(i) == '\\' && i + 1 < n) {
                            i += 2;
                            continue;
                        }
                        i++;
                    }
                    i++; // bỏ dấu " đóng.
                }
                tokens.add("\"\"");
                continue;
            }

            // Punctuator đơn.
            if (c == '{' || c == '}' || c == '(' || c == ')' || c == '[' || c == ']'
                    || c == ':' || c == '=' || c == '@' || c == '$' || c == '!' || c == '&' || c == '|') {
                tokens.add(String.valueOf(c));
                i++;
                continue;
            }

            // Spread "..."
            if (c == '.') {
                if (i + 2 < n && src.charAt(i + 1) == '.' && src.charAt(i + 2) == '.') {
                    tokens.add("...");
                    i += 3;
                    continue;
                }
                i++; // dấu chấm lẻ (số thực) - bỏ qua.
                continue;
            }

            // Name / number / enum / keyword.
            if (Character.isLetterOrDigit(c) || c == '_' || c == '-') {
                int start = i;
                while (i < n) {
                    char d = src.charAt(i);
                    if (Character.isLetterOrDigit(d) || d == '_' || d == '-' || d == '.') {
                        i++;
                    } else {
                        break;
                    }
                }
                tokens.add(src.substring(start, i));
                continue;
            }

            // Ký tự lạ - bỏ qua để giữ tính khoan dung.
            i++;
        }
        return tokens;
    }

    // ===================================================================================
    // AST NODES
    // ===================================================================================

    private static final class Document {
        final List<Operation> operations = new ArrayList<>();
        final Map<String, SelectionSet> fragments = new HashMap<>();
    }

    private static final class Operation {
        final String type;
        final String name;
        final SelectionSet selectionSet;

        Operation(String type, String name, SelectionSet selectionSet) {
            this.type = type;
            this.name = name;
            this.selectionSet = selectionSet;
        }
    }

    private static final class SelectionSet {
        final List<Field> fields = new ArrayList<>();
        final List<String> fragmentSpreads = new ArrayList<>();
        final List<SelectionSet> inlineFragments = new ArrayList<>();
    }

    private static final class Field {
        final String name;
        final List<String> argumentNames = new ArrayList<>();
        SelectionSet selectionSet;

        Field(String name) {
            this.name = name;
        }
    }

    // ===================================================================================
    // RECURSIVE DESCENT PARSER
    // ===================================================================================

    private static final Set<String> OPERATION_KEYWORDS = Set.of("query", "mutation", "subscription");

    private static final class Parser {
        private final List<String> tokens;
        private int pos;

        Parser(List<String> tokens) {
            this.tokens = tokens;
        }

        private String peek() {
            return pos < tokens.size() ? tokens.get(pos) : null;
        }

        private String next() {
            return pos < tokens.size() ? tokens.get(pos++) : null;
        }

        private boolean isName(String t) {
            if (t == null || t.isEmpty()) {
                return false;
            }
            char c = t.charAt(0);
            return Character.isLetter(c) || c == '_';
        }

        Document parseDocument() {
            Document doc = new Document();
            int guard = 0;
            while (peek() != null) {
                if (++guard > tokens.size() + 5) {
                    break; // chống vòng lặp vô hạn nếu logic tiến con trỏ bị kẹt.
                }
                String t = peek();
                if ("fragment".equals(t)) {
                    parseFragmentDefinition(doc);
                } else if (OPERATION_KEYWORDS.contains(t)) {
                    next(); // ăn keyword.
                    Operation op = parseOperationBody(t);
                    if (op != null) {
                        doc.operations.add(op);
                    }
                } else if ("{".equals(t)) {
                    // Shorthand: chỉ có selection set => query ẩn danh.
                    SelectionSet ss = parseSelectionSet();
                    if (ss != null) {
                        doc.operations.add(new Operation("query", "", ss));
                    }
                } else {
                    next(); // token không mong đợi - bỏ qua.
                }
            }
            return doc;
        }

        /** Đã ăn keyword operationType, giờ đọc: [Name] [varDefs] [directives] selectionSet. */
        private Operation parseOperationBody(String type) {
            String name = "";
            String t = peek();
            if (isName(t) && !"{".equals(t)) {
                name = next();
            }
            skipVariableDefinitions();
            skipDirectives();
            SelectionSet ss = parseSelectionSet();
            if (ss == null) {
                return null;
            }
            return new Operation(type, name, ss);
        }

        private void parseFragmentDefinition(Document doc) {
            next(); // ăn "fragment".
            String name = isName(peek()) ? next() : null;
            if ("on".equals(peek())) {
                next();
                if (isName(peek())) {
                    next(); // type condition.
                }
            }
            skipDirectives();
            SelectionSet ss = parseSelectionSet();
            if (name != null && ss != null) {
                doc.fragments.put(name, ss);
            }
        }

        private void skipVariableDefinitions() {
            if ("(".equals(peek())) {
                skipBalanced("(", ")");
            }
        }

        private void skipDirectives() {
            while ("@".equals(peek())) {
                next(); // ăn "@".
                if (isName(peek())) {
                    next(); // tên directive.
                }
                if ("(".equals(peek())) {
                    skipBalanced("(", ")");
                }
            }
        }

        private SelectionSet parseSelectionSet() {
            if (!"{".equals(peek())) {
                return null;
            }
            next(); // ăn "{".
            SelectionSet ss = new SelectionSet();
            int guard = 0;
            while (peek() != null && !"}".equals(peek())) {
                if (++guard > tokens.size() + 5) {
                    break;
                }
                String t = peek();
                if ("...".equals(t)) {
                    parseFragmentUsage(ss);
                } else if (isName(t)) {
                    Field f = parseField();
                    if (f != null) {
                        ss.fields.add(f);
                    }
                } else {
                    next(); // bỏ qua token lạ.
                }
            }
            if ("}".equals(peek())) {
                next(); // ăn "}".
            }
            return ss;
        }

        /** Xử lý "..." – có thể là inline fragment (... on Type {..} / ... {..}) hoặc fragment spread (...Name). */
        private void parseFragmentUsage(SelectionSet parent) {
            next(); // ăn "...".
            if ("on".equals(peek())) {
                next();
                if (isName(peek())) {
                    next(); // type condition.
                }
                skipDirectives();
                SelectionSet inline = parseSelectionSet();
                if (inline != null) {
                    parent.inlineFragments.add(inline);
                }
            } else if ("{".equals(peek())) {
                SelectionSet inline = parseSelectionSet();
                if (inline != null) {
                    parent.inlineFragments.add(inline);
                }
            } else if (isName(peek())) {
                String fragName = next();
                skipDirectives();
                parent.fragmentSpreads.add(fragName);
            }
        }

        private Field parseField() {
            String first = next(); // tên hoặc alias.
            String fieldName = first;
            if (":".equals(peek())) {
                // "first" là alias, tên thật nằm sau dấu ':'.
                next(); // ăn ":".
                if (isName(peek())) {
                    fieldName = next();
                }
            }
            Field field = new Field(fieldName);
            if ("(".equals(peek())) {
                parseArguments(field);
            }
            skipDirectives();
            if ("{".equals(peek())) {
                field.selectionSet = parseSelectionSet();
            }
            return field;
        }

        private void parseArguments(Field field) {
            next(); // ăn "(".
            int guard = 0;
            while (peek() != null && !")".equals(peek())) {
                if (++guard > tokens.size() + 5) {
                    break;
                }
                String t = peek();
                if (isName(t)) {
                    // Chỉ là argument nếu ngay sau tên là dấu ':'.
                    if (pos + 1 < tokens.size() && ":".equals(tokens.get(pos + 1))) {
                        field.argumentNames.add(next()); // tên argument.
                        next(); // ăn ":".
                        skipValue();
                    } else {
                        next();
                    }
                } else {
                    next();
                }
            }
            if (")".equals(peek())) {
                next(); // ăn ")".
            }
        }

        /** Bỏ qua một value của argument (scalar, biến $x, list [...], object {...}). */
        private void skipValue() {
            String t = peek();
            if (t == null) {
                return;
            }
            switch (t) {
                case "[" -> skipBalanced("[", "]");
                case "{" -> skipBalanced("{", "}");
                case "$" -> {
                    next(); // ăn "$".
                    if (isName(peek())) {
                        next();
                    }
                }
                default -> next(); // scalar/enum/string-placeholder/number/keyword.
            }
        }

        private void skipBalanced(String open, String close) {
            if (!open.equals(peek())) {
                return;
            }
            next(); // ăn open.
            int depth = 1;
            int guard = 0;
            while (peek() != null && depth > 0) {
                if (++guard > tokens.size() * 2 + 5) {
                    break;
                }
                String t = next();
                if (open.equals(t)) {
                    depth++;
                } else if (close.equals(t)) {
                    depth--;
                }
            }
        }
    }

    // ===================================================================================
    // FLATTEN + ARG COLLECTION
    // ===================================================================================

    /**
     * Duyệt các root field "hiệu dụng" của một operation (field trực tiếp + field mở ra từ inline
     * fragment và fragment spread ở mức root) rồi gom argument theo TÊN field vào {@code out}.
     * Nhiều alias trỏ tới cùng một field sẽ được hợp nhất argument.
     */
    private static void collectRootFieldArgs(SelectionSet ss, Map<String, SelectionSet> fragments,
                                             Set<String> visitedSpreads, Map<String, Set<String>> out) {
        if (ss == null) {
            return;
        }
        for (Field f : ss.fields) {
            out.computeIfAbsent(f.name, k -> new HashSet<>())
                    .addAll(collectArgs(f, fragments, new HashSet<>()));
        }
        for (SelectionSet inline : ss.inlineFragments) {
            collectRootFieldArgs(inline, fragments, visitedSpreads, out);
        }
        for (String spread : ss.fragmentSpreads) {
            if (visitedSpreads.add(spread)) {
                SelectionSet target = fragments.get(spread);
                if (target != null) {
                    collectRootFieldArgs(target, fragments, visitedSpreads, out);
                }
            }
        }
    }

    /**
     * Thu thập tên của TẤT CẢ argument xuất hiện trong cây con của một field (kể cả trong các
     * fragment được tham chiếu), để tạo thành danh sách injection point của root field đó.
     */
    private static Set<String> collectArgs(Field field, Map<String, SelectionSet> fragments, Set<String> visitedFragments) {
        Set<String> result = new HashSet<>(field.argumentNames);
        if (field.selectionSet != null) {
            result.addAll(collectArgsFromSet(field.selectionSet, fragments, visitedFragments));
        }
        return result;
    }

    private static Set<String> collectArgsFromSet(SelectionSet ss, Map<String, SelectionSet> fragments, Set<String> visitedFragments) {
        Set<String> result = new HashSet<>();
        if (ss == null) {
            return result;
        }
        for (Field f : ss.fields) {
            result.addAll(collectArgs(f, fragments, visitedFragments));
        }
        for (SelectionSet inline : ss.inlineFragments) {
            result.addAll(collectArgsFromSet(inline, fragments, visitedFragments));
        }
        for (String spread : ss.fragmentSpreads) {
            if (visitedFragments.add(spread)) {
                SelectionSet target = fragments.get(spread);
                if (target != null) {
                    result.addAll(collectArgsFromSet(target, fragments, visitedFragments));
                }
            }
        }
        return result;
    }
}
