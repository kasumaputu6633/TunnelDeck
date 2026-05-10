package forwards

import (
	"context"
	"testing"

	"github.com/kasumaputu6633/tunneldeck/internal/db"
)

func TestValidate_GoodMinecraftForward(t *testing.T) {
	protected := BuildProtectedList(22, 51820, 9443)
	nodes := []db.Node{{ID: 1, Name: "home", WGIP: "10.66.66.2"}}

	in := Input{
		Name: "mc-java", Proto: "tcp",
		PublicPort: 25577, NodeID: 1, TargetPort: 25577,
		LogMode: "counter",
	}
	issues := Validate(context.Background(), in, nil, nodes, protected, 0)
	if len(issues) != 0 {
		t.Fatalf("unexpected issues: %+v", issues)
	}
}

func TestValidate_ProtectedPort_SSH_Refuses(t *testing.T) {
	protected := BuildProtectedList(22, 51820, 9443)
	nodes := []db.Node{{ID: 1, Name: "home", WGIP: "10.66.66.2"}}

	in := Input{Name: "oops", Proto: "tcp", PublicPort: 22, NodeID: 1, TargetPort: 22}
	issues := Validate(context.Background(), in, nil, nodes, protected, 0)
	if !HasErrors(issues) {
		t.Fatalf("expected error-level issue for SSH forward, got %+v", issues)
	}
}

func TestValidate_ProtectedPort_DB_OnlyWarns(t *testing.T) {
	protected := BuildProtectedList(22, 51820, 9443)
	nodes := []db.Node{{ID: 1, Name: "home", WGIP: "10.66.66.2"}}

	in := Input{Name: "pg", Proto: "tcp", PublicPort: 5432, NodeID: 1, TargetPort: 5432}
	issues := Validate(context.Background(), in, nil, nodes, protected, 0)
	if HasErrors(issues) {
		t.Fatalf("DB port should be warn-only, got errors: %+v", issues)
	}
	found := false
	for _, i := range issues {
		if i.Severity == "warn" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a warn-level issue, got %+v", issues)
	}
}

func TestValidate_DuplicateProtoPort(t *testing.T) {
	protected := BuildProtectedList(22, 51820, 9443)
	nodes := []db.Node{{ID: 1, Name: "home", WGIP: "10.66.66.2"}}
	existing := []db.Forward{{ID: 42, Proto: "tcp", PublicPort: 25577, NodeID: 1, TargetPort: 25577}}

	in := Input{Name: "dup", Proto: "tcp", PublicPort: 25577, NodeID: 1, TargetPort: 9999}
	issues := Validate(context.Background(), in, existing, nodes, protected, 0)
	if !HasErrors(issues) {
		t.Fatalf("expected duplicate error, got %+v", issues)
	}
}

func TestValidate_DuplicateSkippedWhenEditingSameRow(t *testing.T) {
	protected := BuildProtectedList(22, 51820, 9443)
	nodes := []db.Node{{ID: 1, Name: "home", WGIP: "10.66.66.2"}}
	existing := []db.Forward{{ID: 42, Proto: "tcp", PublicPort: 25577, NodeID: 1, TargetPort: 25577}}

	in := Input{Name: "renamed", Proto: "tcp", PublicPort: 25577, NodeID: 1, TargetPort: 25577}
	issues := Validate(context.Background(), in, existing, nodes, protected, 42) // editing #42
	if HasErrors(issues) {
		t.Fatalf("editing same row should not trigger dup, got %+v", issues)
	}
}

func TestValidate_PortRangeAndNode(t *testing.T) {
	protected := BuildProtectedList(22, 51820, 9443)

	in := Input{Name: "x", Proto: "tcp", PublicPort: 0, NodeID: 99, TargetPort: 70000}
	issues := Validate(context.Background(), in, nil, nil, protected, 0)
	if !HasErrors(issues) {
		t.Fatalf("expected errors for bad ports and missing node, got %+v", issues)
	}
}

func TestAllocateNextIP(t *testing.T) {
	got, err := AllocateNextIP("10.66.66.0/24", "10.66.66.1", []string{"10.66.66.2/32"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.66.66.3" {
		t.Fatalf("got %q want 10.66.66.3", got)
	}
}

func TestAllocateNextIP_SkipsGateway(t *testing.T) {
	got, err := AllocateNextIP("10.66.66.0/24", "10.66.66.1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.66.66.2" {
		t.Fatalf("got %q want 10.66.66.2", got)
	}
}
