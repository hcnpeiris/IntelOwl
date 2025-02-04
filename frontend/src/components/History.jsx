import React, { Suspense } from "react";
import { RiFileListFill } from "react-icons/ri";
import { DiGitMerge } from "react-icons/di";
import { BsFillPlusCircleFill } from "react-icons/bs";
import { Button, Col, Nav, NavItem, TabContent, TabPane } from "reactstrap";
import {
  useNavigate,
  useLocation,
  NavLink as RRNavLink,
} from "react-router-dom";

import { FallBackLoading } from "@certego/certego-ui";
import { useGuideContext } from "../contexts/GuideContext";
import { createInvestigation } from "./investigations/result/investigationApi";

const JobsTable = React.lazy(() => import("./jobs/table/JobsTable"));
const InvestigationsTable = React.lazy(
  () => import("./investigations/table/InvestigationsTable"),
);

export default function History() {
  const navigate = useNavigate();
  const location = useLocation();
  const isJobsTablePage = location?.pathname.includes("jobs");

  const { guideState, setGuideState } = useGuideContext();

  React.useEffect(() => {
    if (guideState.tourActive) {
      setTimeout(() => {
        setGuideState({ run: true, stepIndex: 7 });
      }, 200);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const onClick = async () => {
    if (isJobsTablePage) {
      navigate("/scan");
    } else {
      try {
        const investigationId = await createInvestigation();
        if (investigationId) navigate(`/investigation/${investigationId}`);
      } catch {
        // handle inside createInvestigation
      }
    }
  };

  const createButton = (
    <Col className="d-flex justify-content-end">
      <Button
        id="createbutton"
        className="d-flex align-items-center"
        size="sm"
        color="darker"
        onClick={onClick}
      >
        <BsFillPlusCircleFill />
        &nbsp;Create {isJobsTablePage ? "job" : "investigation"}
      </Button>
    </Col>
  );

  return (
    <>
      <Nav>
        <NavItem>
          <RRNavLink className="nav-link" to="/history/jobs">
            <span id="Jobs">
              <RiFileListFill />
              &nbsp;Jobs
            </span>
          </RRNavLink>
        </NavItem>
        <NavItem>
          <RRNavLink className="nav-link" to="/history/investigations">
            <span id="investigations">
              <DiGitMerge />
              &nbsp;Investigations
            </span>
          </RRNavLink>
        </NavItem>
        {createButton}
      </Nav>
      <TabContent activeTab={isJobsTablePage ? "jobs" : "investigations"}>
        <TabPane tabId="jobs">
          <Suspense fallback={<FallBackLoading />}>
            <JobsTable />
          </Suspense>
        </TabPane>
        <TabPane tabId="investigations">
          <Suspense fallback={<FallBackLoading />}>
            <InvestigationsTable />
          </Suspense>
        </TabPane>
      </TabContent>
    </>
  );
}
