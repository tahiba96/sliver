package generate

import (
	"context"
	"fmt"

	"github.com/bishopfox/sliver/client/console"
	"github.com/bishopfox/sliver/client/forms"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/spf13/cobra"
)

// ImplantsRmCmd - Deletes an archived implant build from the server.
func ImplantsRmCmd(cmd *cobra.Command, con *console.SliverClient, args []string) {
	name := args[0]
	if name == "" {
		con.PrintErrorf("No name specified\n")
		return
	}
	build := ImplantBuildByName(name, con)
	if build == nil {
		con.PrintErrorf("No implant build found with name '%s'\n", name)
		return
	}
	skipConfirm, _ := cmd.Flags().GetBool("yes")
	confirm := skipConfirm
	if !confirm {
		_ = forms.Confirm(fmt.Sprintf("Remove '%s' build?", name), &confirm)
	}
	if !confirm {
		con.PrintInfof("Use --yes to remove a build without the confirmation prompt, or run this in a terminal\n")
		return
	}
	_, err := con.Rpc.DeleteImplantBuild(context.Background(), &clientpb.DeleteReq{
		Name: name,
	})
	if err != nil {
		con.PrintErrorf("Failed to delete implant %s\n", err)
		return
	}
	con.PrintInfof("Successfully removed '%s' build\n", name)
}
